import argparse
import csv
import datetime as dt
import json
import math
import os
import statistics
import sys
import tempfile
import time


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import Config
import crypto_utils
import service
import storage


OUTPUT_DIR = os.path.join(ROOT_DIR, "benchmarks", "output")
CSV_PATH = os.path.join(OUTPUT_DIR, "profile_matrix_results.csv")
JSON_PATH = os.path.join(OUTPUT_DIR, "profile_matrix_results.json")
HTML_PATH = os.path.join(OUTPUT_DIR, "profile_matrix_report.html")

DEFAULT_VOTER_COUNTS = [3, 5, 10, 25]
DEFAULT_CANDIDATE_COUNTS = [2, 3, 5]

PROFILE_CONFIGS = {
    "basic": {
        "mode": "simple",
        "threshold": 0,
        "authority_count": 0,
        "use_homomorphic_results": False,
        "description": "Базовый режим с аутентифицированной записью голоса в блокчейн.",
        "mechanisms": [
            "Реестр избирателей и аутентификация по PIN",
            "Открытая запись выбора в blockchain audit trail",
            "Проверка целостности цепочки и публикация базового результата",
        ],
    },
    "standard": {
        "mode": "encrypted",
        "threshold": 0,
        "authority_count": 0,
        "use_homomorphic_results": False,
        "description": "Анонимный токен, зашифрованный бюллетень и базовая публикация результата.",
        "mechanisms": [
            "Blind-signature token issuance",
            "Зашифрованный бюллетень и квитанционная проверка",
            "Blockchain bulletin board и базовая публикация результата",
        ],
    },
    "high_assurance": {
        "mode": "encrypted",
        "threshold": 2,
        "authority_count": 3,
        "use_homomorphic_results": True,
        "description": "Blind signature, encrypted ballot, homomorphic tally и threshold evidence 2-of-3.",
        "mechanisms": [
            "Blind-signature authorization",
            "Encrypted ballot и one-hot proof-bearing ballot validation",
            "Homomorphic tally и threshold-supported publication 2-of-3",
            "Blockchain audit trail, bulletin board и validation endpoints",
        ],
    },
    "maximum_protection": {
        "mode": "encrypted",
        "threshold": 3,
        "authority_count": 5,
        "use_homomorphic_results": True,
        "description": "Усиленный пороговый контур с конфигурацией 3-of-5.",
        "mechanisms": [
            "Blind-signature authorization",
            "Encrypted ballot и proof-bearing ballot validation",
            "Homomorphic tally и усиленный threshold-supported publication 3-of-5",
            "Blockchain audit trail, bulletin board и chain validation",
        ],
    },
}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Run visual constructor profile benchmarks across voters and candidate counts."
    )
    parser.add_argument(
        "--profiles",
        nargs="*",
        default=list(PROFILE_CONFIGS.keys()),
        help="Profiles to benchmark.",
    )
    parser.add_argument(
        "--voters",
        nargs="*",
        type=int,
        default=DEFAULT_VOTER_COUNTS,
        help="Voter counts to benchmark.",
    )
    parser.add_argument(
        "--candidates",
        nargs="*",
        type=int,
        default=DEFAULT_CANDIDATE_COUNTS,
        help="Candidate counts to benchmark.",
    )
    parser.add_argument(
        "--max-scenarios",
        type=int,
        default=None,
        help="Optional cap on total scenarios for quick runs.",
    )
    return parser.parse_args()


def make_accounts(count):
    rows = []
    for index in range(1, count + 1):
        voter_id = "MATRIX{:04d}".format(index)
        pin = "{:04d}".format((2000 + index) % 10000)
        rows.append(
            {
                "voter_id": voter_id,
                "pin": pin,
                "pin_hash": storage.hash_pin(pin),
                "role": "voter",
                "is_active": True,
            }
        )
    return rows


def seed_accounts(rows):
    connection = storage.get_connection()
    try:
        now = time.time()
        connection.executemany(
            """
            INSERT INTO voters (voter_id, pin_hash, role, is_active, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                (row["voter_id"], row["pin_hash"], row["role"], 1 if row["is_active"] else 0, now)
                for row in rows
            ],
        )
        connection.commit()
    finally:
        connection.close()


def make_candidate_options(count):
    return ["Candidate {:02d}".format(index) for index in range(1, count + 1)]


def configure_active_election(candidate_count, security_profile):
    active = storage.get_active_election()
    if active:
        storage.update_election_status(active["id"], "closed")
    storage.create_election(
        "Matrix Benchmark {} candidates {}".format(security_profile, candidate_count),
        make_candidate_options(candidate_count),
        security_profile,
        status="active",
    )
    return storage.get_active_election()


def reset_service_state(db_path, profile_key):
    config = PROFILE_CONFIGS[profile_key]
    storage.set_database_path(db_path)
    storage.initialize_storage(reset=True)
    service.peers = set()
    service.app.config["TESTING"] = True

    if config["authority_count"]:
        Config.TALLY_AUTHORITY_COUNT = config["authority_count"]
        Config.TALLY_THRESHOLD = config["threshold"]
        service.app.config["TALLY_AUTHORITY_COUNT"] = config["authority_count"]
        service.app.config["TALLY_THRESHOLD"] = config["threshold"]
    else:
        Config.TALLY_AUTHORITY_COUNT = 3
        Config.TALLY_THRESHOLD = 2
        service.app.config["TALLY_AUTHORITY_COUNT"] = 3
        service.app.config["TALLY_THRESHOLD"] = 2

    service.blockchain = service.load_blockchain()


def progress_bar(current, total, width=28):
    ratio = current / total if total else 0
    filled = int(ratio * width)
    return "[{}{}]".format("#" * filled, "." * (width - filled))


def iso_now():
    return dt.datetime.now().isoformat(timespec="seconds")


def run_scenario(profile_key, voter_count, candidate_count):
    config = PROFILE_CONFIGS[profile_key]
    with tempfile.TemporaryDirectory() as temp_dir:
        db_path = os.path.join(temp_dir, "profile_matrix.db")
        reset_service_state(db_path, profile_key)
        election = configure_active_election(candidate_count, profile_key)
        accounts = make_accounts(voter_count)
        seed_accounts(accounts)
        client = service.app.test_client()

        phase_totals = {
            "auth_total": 0.0,
            "token_total": 0.0,
            "cast_total": 0.0,
            "verify_total": 0.0,
            "mine_time": 0.0,
            "results_time": 0.0,
            "homomorphic_results_time": 0.0,
            "validate_time": 0.0,
            "bulletin_board_time": 0.0,
        }
        receipt_hashes = []
        scenario_started = time.perf_counter()

        for index, account in enumerate(accounts):
            voter_id = account["voter_id"]
            pin = account["pin"]
            voter_hash = storage.hash_voter_id(voter_id)
            selected_option = election["options"][index % len(election["options"])]

            started = time.perf_counter()
            authenticated = storage.authenticate_user(voter_id, pin)
            phase_totals["auth_total"] += time.perf_counter() - started
            if not authenticated:
                raise RuntimeError("Authentication failed for {}".format(voter_id))

            if config["mode"] == "simple":
                started = time.perf_counter()
                response = client.post(
                    "/new_transaction",
                    json={
                        "election_id": election["id"],
                        "voter_hash": voter_hash,
                        "party": selected_option,
                    },
                )
                phase_totals["cast_total"] += time.perf_counter() - started
                if response.status_code != 201:
                    raise RuntimeError("Simple ballot cast failed for {}".format(voter_id))
            else:
                token_message = crypto_utils.generate_token_message()
                blinded = crypto_utils.blind_token_message(token_message)
                started = time.perf_counter()
                issue_response = client.post(
                    "/issue_token",
                    json={
                        "election_id": election["id"],
                        "voter_hash": voter_hash,
                        "blinded_token": blinded["blinded_token"],
                    },
                )
                phase_totals["token_total"] += time.perf_counter() - started
                if issue_response.status_code != 201:
                    raise RuntimeError("Token issuance failed for {}".format(voter_id))

                blind_signature = issue_response.get_json()["blind_signature"]
                token_signature = crypto_utils.unblind_signature(blind_signature, blinded["blind_factor"])
                encrypted_ballot = crypto_utils.encrypt_ballot_payload(
                    {
                        "election_id": election["id"],
                        "selection": selected_option,
                        "nonce": "matrix-{}-{}".format(candidate_count, index),
                    }
                )
                homomorphic_ballot = crypto_utils.build_homomorphic_ballot(election["options"], selected_option)
                receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
                started = time.perf_counter()
                cast_response = client.post(
                    "/cast_ballot",
                    json={
                        "election_id": election["id"],
                        "token_message": token_message,
                        "token_signature": token_signature,
                        "encrypted_ballot": encrypted_ballot,
                        "receipt_hash": receipt_hash,
                        "homomorphic_ballot": homomorphic_ballot,
                    },
                )
                phase_totals["cast_total"] += time.perf_counter() - started
                if cast_response.status_code != 201:
                    raise RuntimeError("Encrypted ballot cast failed for {}".format(voter_id))
                receipt_hashes.append(receipt_hash)

        started = time.perf_counter()
        mine_response = client.get("/mine")
        phase_totals["mine_time"] = time.perf_counter() - started
        if mine_response.status_code != 200:
            raise RuntimeError("Mining failed for profile {}".format(profile_key))

        if receipt_hashes:
            for receipt_hash in receipt_hashes:
                started = time.perf_counter()
                verify_response = client.get("/verify_receipt/{}".format(receipt_hash))
                phase_totals["verify_total"] += time.perf_counter() - started
                if verify_response.status_code not in {200, 404}:
                    raise RuntimeError("Receipt verification failed")

        started = time.perf_counter()
        results_response = client.get("/results")
        phase_totals["results_time"] = time.perf_counter() - started
        if results_response.status_code != 200:
            raise RuntimeError("Results fetch failed")

        if config["use_homomorphic_results"]:
            started = time.perf_counter()
            homomorphic_response = client.get("/homomorphic_results")
            phase_totals["homomorphic_results_time"] = time.perf_counter() - started
            if homomorphic_response.status_code != 200:
                raise RuntimeError("Homomorphic results fetch failed")
            homomorphic_payload = homomorphic_response.get_json()
            proof_artifact_count = len(homomorphic_payload.get("threshold", {}).get("proof_artifacts", []))
        else:
            proof_artifact_count = 0

        started = time.perf_counter()
        validate_response = client.get("/validate")
        phase_totals["validate_time"] = time.perf_counter() - started
        if validate_response.status_code != 200:
            raise RuntimeError("Validate chain failed")

        started = time.perf_counter()
        bulletin_response = client.get("/bulletin_board")
        phase_totals["bulletin_board_time"] = time.perf_counter() - started
        if bulletin_response.status_code != 200:
            raise RuntimeError("Bulletin board fetch failed")

        total_time = time.perf_counter() - scenario_started
        bottleneck_key = max(phase_totals, key=lambda key: phase_totals[key])
        return {
            "profile": profile_key,
            "profile_description": config["description"],
            "mode": config["mode"],
            "voter_count": voter_count,
            "candidate_count": candidate_count,
            "authority_count": config["authority_count"],
            "threshold": config["threshold"],
            "auth_total": phase_totals["auth_total"],
            "token_total": phase_totals["token_total"],
            "cast_total": phase_totals["cast_total"],
            "verify_total": phase_totals["verify_total"],
            "mine_time": phase_totals["mine_time"],
            "results_time": phase_totals["results_time"],
            "homomorphic_results_time": phase_totals["homomorphic_results_time"],
            "validate_time": phase_totals["validate_time"],
            "bulletin_board_time": phase_totals["bulletin_board_time"],
            "total_time": total_time,
            "bottleneck_phase": bottleneck_key,
            "bottleneck_time": phase_totals[bottleneck_key],
            "proof_artifact_count": proof_artifact_count,
            "chain_length": len(service.blockchain.chain),
        }


def write_csv(rows):
    ensure_output_dir()
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with open(CSV_PATH, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def profile_summary(rows):
    grouped = {}
    for profile in PROFILE_CONFIGS:
        subset = [row for row in rows if row["profile"] == profile]
        if not subset:
            continue
        grouped[profile] = {
            "scenario_count": len(subset),
            "mean_total_time": statistics.mean(row["total_time"] for row in subset),
            "max_total_time": max(row["total_time"] for row in subset),
            "mean_cast_time": statistics.mean(row["cast_total"] for row in subset),
            "mean_results_time": statistics.mean(
                row["results_time"] + row["homomorphic_results_time"] for row in subset
            ),
            "dominant_bottleneck": statistics.mode([row["bottleneck_phase"] for row in subset])
            if len({row["bottleneck_phase"] for row in subset}) < len(subset)
            else max(
                set(row["bottleneck_phase"] for row in subset),
                key=lambda key: sum(1 for row in subset if row["bottleneck_phase"] == key),
            ),
        }
    return grouped


def write_json(status, rows, started_at, finished_at=None):
    ensure_output_dir()
    payload = {
        "status": status,
        "started_at": started_at,
        "finished_at": finished_at,
        "rows": rows,
        "profile_summary": profile_summary(rows),
    }
    with open(JSON_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)


def html_escape(value):
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def format_seconds(value):
    return "{:.3f}s".format(value)


PHASE_LABELS = {
    "auth_total": "Auth",
    "token_total": "Token",
    "cast_total": "Cast",
    "verify_total": "Verify",
    "mine_time": "Mine",
    "results_time": "Results",
    "homomorphic_results_time": "Homomorphic",
    "validate_time": "Validate",
    "bulletin_board_time": "Bulletin",
}


def bar_color(profile):
    palette = {
        "basic": "#547a6a",
        "standard": "#b8793f",
        "high_assurance": "#8e4b4b",
        "maximum_protection": "#3f5f8e",
    }
    return palette.get(profile, "#547a6a")


def intensity_color(value, max_value):
    if max_value <= 0:
        return "#f5f2ea"
    ratio = min(1.0, value / max_value)
    if ratio < 0.2:
        return "#eef4ef"
    if ratio < 0.4:
        return "#d8e8db"
    if ratio < 0.6:
        return "#bfd3c5"
    if ratio < 0.8:
        return "#d7bea0"
    return "#c88f63"


def render_metric_bars(summary, metric_key, title):
    if not summary:
        return ""
    max_value = max(item[metric_key] for item in summary.values()) or 1.0
    rows_html = []
    for profile, item in summary.items():
        value = item[metric_key]
        width = (value / max_value) * 100.0 if max_value else 0.0
        rows_html.append(
            """
            <div class="bar-row">
              <div class="bar-meta">
                <span class="bar-label">{profile}</span>
                <span class="bar-value">{value}</span>
              </div>
              <div class="bar-track">
                <div class="bar-fill" style="width:{width:.2f}%; background:{color};"></div>
              </div>
            </div>
            """.format(
                profile=html_escape(profile),
                value=format_seconds(value),
                width=width,
                color=bar_color(profile),
            )
        )
    return """
    <section class="viz-card">
      <h3>{title}</h3>
      {rows}
    </section>
    """.format(title=html_escape(title), rows="".join(rows_html))


def render_bottleneck_heatmap(rows):
    if not rows:
        return ""
    phases = list(PHASE_LABELS.keys())
    grouped = {}
    for row in rows:
        profile = row["profile"]
        grouped.setdefault(profile, {phase: 0 for phase in phases})
        grouped[profile][row["bottleneck_phase"]] += 1
    max_count = max(
        count
        for counts in grouped.values()
        for count in counts.values()
    ) or 1
    body_rows = []
    for profile in PROFILE_CONFIGS:
        if profile not in grouped:
            continue
        cells = []
        for phase in phases:
            count = grouped[profile][phase]
            cells.append(
                '<td style="background:{bg};">{count}</td>'.format(
                    bg=intensity_color(count, max_count),
                    count=count,
                )
            )
        body_rows.append(
            "<tr><th>{profile}</th>{cells}</tr>".format(
                profile=html_escape(profile),
                cells="".join(cells),
            )
        )
    header = "".join("<th>{}</th>".format(html_escape(PHASE_LABELS[phase])) for phase in phases)
    return """
    <section class="viz-card">
      <h3>Тепловая карта узких мест</h3>
      <p class="meta">Число сценариев, в которых соответствующая стадия была самой дорогой для профиля.</p>
      <table class="compact-table">
        <thead>
          <tr><th>Профиль</th>{header}</tr>
        </thead>
        <tbody>
          {rows}
        </tbody>
      </table>
    </section>
    """.format(header=header, rows="".join(body_rows))


def render_scenario_heatmaps(rows):
    if not rows:
        return ""
    blocks = []
    for profile in PROFILE_CONFIGS:
        subset = [row for row in rows if row["profile"] == profile]
        if not subset:
            continue
        voter_counts = sorted({row["voter_count"] for row in subset})
        candidate_counts = sorted({row["candidate_count"] for row in subset})
        matrix = {
            (row["candidate_count"], row["voter_count"]): row
            for row in subset
        }
        max_total = max(row["total_time"] for row in subset) or 1.0
        body_rows = []
        for candidate_count in candidate_counts:
            cells = []
            for voter_count in voter_counts:
                row = matrix.get((candidate_count, voter_count))
                if row is None:
                    cells.append("<td>—</td>")
                    continue
                cells.append(
                    '<td style="background:{bg};"><div>{time}</div><div class="cell-sub">{phase}</div></td>'.format(
                        bg=intensity_color(row["total_time"], max_total),
                        time=format_seconds(row["total_time"]),
                        phase=html_escape(PHASE_LABELS.get(row["bottleneck_phase"], row["bottleneck_phase"])),
                    )
                )
            body_rows.append(
                "<tr><th>{candidate_count}</th>{cells}</tr>".format(
                    candidate_count=candidate_count,
                    cells="".join(cells),
                )
            )
        header = "".join("<th>{}</th>".format(voter_count) for voter_count in voter_counts)
        blocks.append(
            """
            <section class="viz-card">
              <h3>Матрица сценариев: {profile}</h3>
              <p class="meta">{description}</p>
              <table class="compact-table">
                <thead>
                  <tr><th>Кандидаты \\ Голосующие</th>{header}</tr>
                </thead>
                <tbody>
                  {rows}
                </tbody>
              </table>
            </section>
            """.format(
                profile=html_escape(profile),
                description=html_escape(PROFILE_CONFIGS[profile]["description"]),
                header=header,
                rows="".join(body_rows),
            )
        )
    return "".join(blocks)


def render_profile_protocols():
    cards = []
    for profile in PROFILE_CONFIGS:
        config = PROFILE_CONFIGS[profile]
        bullets = "".join(
            "<li>{}</li>".format(html_escape(item))
            for item in config.get("mechanisms", [])
        )
        threshold_text = (
            "не используется"
            if not config["authority_count"]
            else "{}-of-{}".format(config["threshold"], config["authority_count"])
        )
        cards.append(
            """
            <div class="card">
              <h3>{profile}</h3>
              <p>{description}</p>
              <p><strong>Режим:</strong> {mode}</p>
              <p><strong>Threshold-контур:</strong> {threshold}</p>
              <ul class="mechanism-list">
                {bullets}
              </ul>
            </div>
            """.format(
                profile=html_escape(profile),
                description=html_escape(config["description"]),
                mode=html_escape(config["mode"]),
                threshold=html_escape(threshold_text),
                bullets=bullets,
            )
        )
    return """
    <section class="viz-card">
      <h2>Профили и используемые механизмы</h2>
      <p class="meta">Ниже показано, какие протоколы и блокчейн-компоненты реально включаются в каждом профиле конструктора.</p>
      <div class="grid">
        {cards}
      </div>
    </section>
    """.format(cards="".join(cards))


def render_profile_comparison_chart(summary):
    if not summary:
        return ""
    profiles = [profile for profile in PROFILE_CONFIGS if profile in summary]
    if not profiles:
        return ""
    max_value = max(summary[profile]["mean_total_time"] for profile in profiles) or 1.0
    width = 920
    height = 360
    margin_left = 70
    margin_bottom = 50
    chart_height = 240
    chart_base_y = height - margin_bottom
    group_width = 170
    bar_width = 48
    gap = 18
    x_start = 100
    total_bars = []
    results_bars = []
    labels = []
    for index, profile in enumerate(profiles):
        x_group = x_start + index * group_width
        total_value = summary[profile]["mean_total_time"]
        results_value = summary[profile]["mean_results_time"]
        total_height = (total_value / max_value) * chart_height
        results_height = (results_value / max_value) * chart_height
        total_x = x_group
        results_x = x_group + bar_width + gap
        total_bars.append(
            '<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" rx="6"/>'.format(
                x=total_x,
                y=chart_base_y - total_height,
                w=bar_width,
                h=total_height,
                fill=bar_color(profile),
            )
        )
        results_bars.append(
            '<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="#d9a56a" rx="6"/>'.format(
                x=results_x,
                y=chart_base_y - results_height,
                w=bar_width,
                h=results_height,
                fill="#d9a56a",
            )
        )
        labels.append(
            '<text x="{x}" y="{y}" text-anchor="middle" font-size="12" fill="#243330">{label}</text>'.format(
                x=x_group + bar_width + gap / 2,
                y=chart_base_y + 22,
                label=html_escape(profile),
            )
        )
    y_ticks = []
    for tick in range(0, 5):
        value = max_value * tick / 4
        y = chart_base_y - chart_height * tick / 4
        y_ticks.append(
            '<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="#ddd6c8" stroke-width="1"/><text x="56" y="{ty}" text-anchor="end" font-size="12" fill="#5c6d69">{value:.1f}</text>'.format(
                x1=margin_left,
                x2=width - 30,
                y=y,
                ty=y + 4,
                value=value,
            )
        )
    svg = """
    <svg viewBox="0 0 {width} {height}" class="chart-svg" role="img" aria-label="Сравнительный график профилей">
      <line x1="{margin_left}" y1="{chart_base_y}" x2="{x2}" y2="{chart_base_y}" stroke="#8a948f" stroke-width="1.5"/>
      <line x1="{margin_left}" y1="30" x2="{margin_left}" y2="{chart_base_y}" stroke="#8a948f" stroke-width="1.5"/>
      {y_ticks}
      {total_bars}
      {results_bars}
      {labels}
      <rect x="680" y="26" width="16" height="16" fill="#547a6a" rx="4"/>
      <text x="704" y="39" font-size="12" fill="#243330">Среднее полное время</text>
      <rect x="680" y="52" width="16" height="16" fill="#d9a56a" rx="4"/>
      <text x="704" y="65" font-size="12" fill="#243330">Среднее время публикации результата</text>
    </svg>
    """.format(
        width=width,
        height=height,
        margin_left=margin_left,
        chart_base_y=chart_base_y,
        x2=width - 30,
        y_ticks="".join(y_ticks),
        total_bars="".join(total_bars),
        results_bars="".join(results_bars),
        labels="".join(labels),
    )
    return """
    <section class="viz-card">
      <h3>Сравнительный график профилей</h3>
      <p class="meta">График показывает вычислительную цену каждого профиля конструктора. Более высокий столбец означает, что соответствующий уровень защищенности требует большего времени выполнения. Зеленые столбцы отражают среднее полное время сценария, а песочные столбцы показывают, какая часть этой цены приходится на публикацию результата. Тем самым график позволяет увидеть, как усиление приватности, проверяемости и пороговой поддержки увеличивает общую стоимость голосования.</p>
      {svg}
    </section>
    """.format(svg=svg)


def render_html(status, rows, started_at, finished_at=None, total_scenarios=None):
    summary = profile_summary(rows)
    complete = len(rows)
    total = total_scenarios or complete
    progress = (complete / total * 100.0) if total else 0.0

    summary_cards = []
    for profile, item in summary.items():
        summary_cards.append(
            """
            <div class="card">
              <h3>{profile}</h3>
              <p>{count} scenarios</p>
              <p>Среднее полное время: <strong>{mean_total}</strong></p>
              <p>Среднее время подачи: <strong>{mean_cast}</strong></p>
              <p>Доминирующее узкое место: <strong>{bottleneck}</strong></p>
            </div>
            """.format(
                profile=html_escape(profile),
                count=item["scenario_count"],
                mean_total=format_seconds(item["mean_total_time"]),
                mean_cast=format_seconds(item["mean_cast_time"]),
                bottleneck=html_escape(item["dominant_bottleneck"]),
            )
        )

    metric_blocks = [
        render_metric_bars(summary, "mean_total_time", "Среднее полное время сценария по профилям"),
        render_metric_bars(summary, "mean_cast_time", "Среднее время подачи бюллетеня по профилям"),
        render_metric_bars(summary, "mean_results_time", "Среднее время публикации результата по профилям"),
    ]
    protocol_block = render_profile_protocols()
    comparison_chart = render_profile_comparison_chart(summary)
    bottleneck_block = render_bottleneck_heatmap(rows)
    scenario_heatmaps = render_scenario_heatmaps(rows)

    table_rows = []
    for row in rows:
        table_rows.append(
            """
            <tr>
              <td>{profile}</td>
              <td>{candidates}</td>
              <td>{voters}</td>
              <td>{mode}</td>
              <td>{threshold}</td>
              <td>{authorities}</td>
              <td>{auth}</td>
              <td>{token}</td>
              <td>{cast}</td>
              <td>{verify}</td>
              <td>{mine}</td>
              <td>{results}</td>
              <td>{homo}</td>
              <td>{total}</td>
              <td><strong>{bottleneck}</strong></td>
            </tr>
            """.format(
                profile=html_escape(row["profile"]),
                candidates=row["candidate_count"],
                voters=row["voter_count"],
                mode=html_escape(row["mode"]),
                threshold=row["threshold"],
                authorities=row["authority_count"],
                auth=format_seconds(row["auth_total"]),
                token=format_seconds(row["token_total"]),
                cast=format_seconds(row["cast_total"]),
                verify=format_seconds(row["verify_total"]),
                mine=format_seconds(row["mine_time"]),
                results=format_seconds(row["results_time"]),
                homo=format_seconds(row["homomorphic_results_time"]),
                total=format_seconds(row["total_time"]),
                bottleneck=html_escape(row["bottleneck_phase"]),
            )
        )

    html = """
    <!doctype html>
    <html lang="ru">
    <head>
      <meta charset="utf-8"/>
      <title>Constructor Profile Benchmark</title>
      <style>
        body {{
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0;
          background: #f6f4ee;
          color: #243330;
        }}
        .wrap {{
          max-width: 1280px;
          margin: 0 auto;
          padding: 32px;
        }}
        .hero {{
          background: linear-gradient(135deg, #e8efe7, #f8f4e9);
          border: 1px solid #d5d0c2;
          border-radius: 20px;
          padding: 24px 28px;
        }}
        .progress {{
          margin-top: 16px;
          background: #e1ddd1;
          border-radius: 999px;
          overflow: hidden;
          height: 16px;
        }}
        .progress > div {{
          height: 100%;
          width: {progress:.2f}%;
          background: linear-gradient(90deg, #1f5c57, #7aa08f);
        }}
        .grid {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
          gap: 16px;
          margin-top: 24px;
        }}
        .card {{
          background: white;
          border: 1px solid #d7d1c5;
          border-radius: 18px;
          padding: 18px;
        }}
        .mechanism-list {{
          margin: 12px 0 0;
          padding-left: 18px;
        }}
        .mechanism-list li {{
          margin-top: 6px;
          line-height: 1.4;
        }}
        .viz-grid {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
          gap: 16px;
          margin-top: 24px;
        }}
        .viz-card {{
          background: white;
          border: 1px solid #d7d1c5;
          border-radius: 18px;
          padding: 18px;
          margin-top: 24px;
        }}
        .bar-row {{
          margin-top: 14px;
        }}
        .bar-meta {{
          display: flex;
          justify-content: space-between;
          gap: 10px;
          font-size: 14px;
          margin-bottom: 6px;
        }}
        .bar-label {{
          font-weight: 600;
        }}
        .bar-track {{
          background: #ece7db;
          height: 14px;
          border-radius: 999px;
          overflow: hidden;
        }}
        .bar-fill {{
          height: 100%;
          border-radius: 999px;
        }}
        .chart-svg {{
          width: 100%;
          height: auto;
          display: block;
          margin-top: 10px;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          margin-top: 28px;
          background: white;
          border-radius: 18px;
          overflow: hidden;
        }}
        th, td {{
          padding: 12px 10px;
          border-bottom: 1px solid #ece7db;
          font-size: 14px;
          text-align: left;
        }}
        th {{
          background: #f1ede3;
          position: sticky;
          top: 0;
        }}
        .compact-table {{
          margin-top: 14px;
        }}
        .compact-table th, .compact-table td {{
          text-align: center;
          font-size: 13px;
          position: static;
        }}
        .compact-table th:first-child, .compact-table td:first-child {{
          text-align: left;
        }}
        .cell-sub {{
          color: #5c6d69;
          font-size: 11px;
          margin-top: 4px;
        }}
        .meta {{
          color: #5c6d69;
          font-size: 14px;
        }}
        .note {{
          margin-top: 20px;
          background: #fffdf8;
          border-left: 4px solid #b8793f;
          padding: 16px 18px;
        }}
      </style>
    </head>
    <body>
      <div class="wrap">
        <section class="hero">
          <h1>Визуальный benchmark конструктора голосования</h1>
          <p class="meta">Статус: <strong>{status}</strong> | Начало: {started_at} | Завершено сценариев: {complete}/{total}</p>
          <div class="progress"><div></div></div>
          <p class="meta">Отчет обновляется после каждого завершенного сценария. Если открыт в браузере, обновите страницу для просмотра нового состояния.</p>
        </section>
        <section class="grid">
          {summary_cards}
        </section>
        {protocol_block}
        <section class="note">
          <strong>Как читать отчет.</strong> Каждая строка ниже соответствует одному полному запуску профиля на фиксированной конфигурации числа кандидатов и голосующих. Столбец <em>bottleneck</em> показывает стадию, которая заняла наибольшее время и выступает узким местом сценария.
        </section>
        {comparison_chart}
        <section class="viz-grid">
          {metric_blocks}
        </section>
        {bottleneck_block}
        {scenario_heatmaps}
        <table>
          <thead>
            <tr>
              <th>Профиль</th>
              <th>Кандидаты</th>
              <th>Голосующие</th>
              <th>Режим</th>
              <th>Threshold</th>
              <th>Authorities</th>
              <th>Auth</th>
              <th>Token</th>
              <th>Cast</th>
              <th>Verify</th>
              <th>Mine</th>
              <th>Results</th>
              <th>Homo</th>
              <th>Total</th>
              <th>Bottleneck</th>
            </tr>
          </thead>
          <tbody>
            {table_rows}
          </tbody>
        </table>
      </div>
    </body>
    </html>
    """.format(
        progress=progress,
        status=html_escape(status),
        started_at=html_escape(started_at),
        complete=complete,
        total=total,
        summary_cards="".join(summary_cards),
        protocol_block=protocol_block,
        comparison_chart=comparison_chart,
        metric_blocks="".join(block for block in metric_blocks if block),
        bottleneck_block=bottleneck_block,
        scenario_heatmaps=scenario_heatmaps,
        table_rows="".join(table_rows),
    )
    with open(HTML_PATH, "w", encoding="utf-8") as handle:
        handle.write(html)


def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def update_outputs(status, rows, started_at, finished_at=None, total_scenarios=None):
    write_csv(rows)
    write_json(status, rows, started_at, finished_at=finished_at)
    render_html(status, rows, started_at, finished_at=finished_at, total_scenarios=total_scenarios)


def scenario_matrix(profiles, candidate_counts, voter_counts, max_scenarios=None):
    matrix = []
    for profile in profiles:
        for candidate_count in candidate_counts:
            for voter_count in voter_counts:
                matrix.append((profile, candidate_count, voter_count))
    if max_scenarios is not None:
        return matrix[:max_scenarios]
    return matrix


def console_progress(index, total, row, elapsed, avg_time):
    eta = max(0.0, (total - index) * avg_time)
    message = (
        "{bar} {idx}/{total} | profile={profile} | candidates={candidates} | voters={voters} | "
        "total={total_time} | bottleneck={bottleneck} ({bottleneck_time}) | ETA {eta}"
    ).format(
        bar=progress_bar(index, total),
        idx=index,
        total=total,
        profile=row["profile"],
        candidates=row["candidate_count"],
        voters=row["voter_count"],
        total_time=format_seconds(row["total_time"]),
        bottleneck=row["bottleneck_phase"],
        bottleneck_time=format_seconds(row["bottleneck_time"]),
        eta=format_seconds(eta),
    )
    print(message)
    print(
        "  phases: auth={auth} token={token} cast={cast} verify={verify} mine={mine} results={results} homo={homo}".format(
            auth=format_seconds(row["auth_total"]),
            token=format_seconds(row["token_total"]),
            cast=format_seconds(row["cast_total"]),
            verify=format_seconds(row["verify_total"]),
            mine=format_seconds(row["mine_time"]),
            results=format_seconds(row["results_time"]),
            homo=format_seconds(row["homomorphic_results_time"]),
        )
    )
    print("  elapsed since start: {}".format(format_seconds(elapsed)))


def main():
    args = parse_args()
    profiles = [profile for profile in args.profiles if profile in PROFILE_CONFIGS]
    matrix = scenario_matrix(profiles, args.candidates, args.voters, args.max_scenarios)
    started_at = iso_now()
    rows = []
    ensure_output_dir()
    update_outputs("running", rows, started_at, total_scenarios=len(matrix))
    run_started = time.perf_counter()

    print("Starting constructor profile benchmark")
    print("Profiles: {}".format(", ".join(profiles)))
    print("Candidate counts: {}".format(", ".join(str(value) for value in args.candidates)))
    print("Voter counts: {}".format(", ".join(str(value) for value in args.voters)))
    print("Total scenarios: {}".format(len(matrix)))
    print("Live HTML report: {}".format(HTML_PATH))
    print()

    for index, (profile, candidate_count, voter_count) in enumerate(matrix, start=1):
        row = run_scenario(profile, voter_count=voter_count, candidate_count=candidate_count)
        rows.append(row)
        elapsed = time.perf_counter() - run_started
        avg_time = elapsed / index
        console_progress(index, len(matrix), row, elapsed, avg_time)
        update_outputs("running", rows, started_at, total_scenarios=len(matrix))

    finished_at = iso_now()
    update_outputs("completed", rows, started_at, finished_at=finished_at, total_scenarios=len(matrix))
    print()
    print("Benchmark complete.")
    print("CSV: {}".format(CSV_PATH))
    print("JSON: {}".format(JSON_PATH))
    print("HTML: {}".format(HTML_PATH))


if __name__ == "__main__":
    main()
