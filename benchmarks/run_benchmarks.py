import argparse
import csv
import os
import sys
import statistics
import tempfile
import time
from collections import defaultdict

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from config import Config
import crypto_utils
import service
import storage


SCALES = [5, 10, 25, 50, 100, 250]
OPTION_COUNTS = [3, 5, 10]
AUTHORITY_CONFIGS = [(2, 3), (3, 5)]
REPEATS = 5
DEFAULT_PROJECTION_SCALES = [1000, 10000, 100000, 1000000, 10000000, 100000000]
BENCHMARK_OUTPUT_PATH = "benchmarks/output/benchmark_results.csv"
PROJECTION_OUTPUT_PATH = "benchmarks/output/benchmark_projection.csv"
COMPARISON_OUTPUT_PATH = "benchmarks/output/benchmark_comparison.csv"


def make_election_options(count):
    return ["Option {:02d}".format(index) for index in range(1, count + 1)]


def configure_benchmark_election(option_count, security_profile="high_assurance"):
    active_election = storage.get_active_election()
    if active_election:
        storage.update_election_status(active_election["id"], "closed")
    election_id = storage.create_election(
        "Benchmark Election {} Options".format(option_count),
        make_election_options(option_count),
        security_profile,
        status="active",
    )
    return storage.get_active_election()


def make_benchmark_accounts(count):
    rows = []
    for index in range(1, count + 1):
        voter_id = "BENCH{:04d}".format(index)
        pin = "{:04d}".format((1000 + index) % 10000)
        rows.append(
            {
                "voter_id": voter_id,
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


def benchmark_once(voter_count, option_count=3, authority_count=3, threshold=2):
    with tempfile.TemporaryDirectory() as temp_dir:
        original_threshold = Config.TALLY_THRESHOLD
        original_authority_count = Config.TALLY_AUTHORITY_COUNT
        db_path = os.path.join(temp_dir, "bench.db")
        Config.TALLY_THRESHOLD = threshold
        Config.TALLY_AUTHORITY_COUNT = authority_count
        try:
            storage.set_database_path(db_path)
            storage.initialize_storage(reset=True)
            service.app.config["TALLY_THRESHOLD"] = threshold
            service.app.config["TALLY_AUTHORITY_COUNT"] = authority_count
            service.blockchain = service.load_blockchain()
            service.peers = set()
            election = configure_benchmark_election(option_count)
            seed_accounts(make_benchmark_accounts(voter_count))
            client = service.app.test_client()

            auth_times = []
            token_times = []
            cast_times = []
            verify_times = []
            mine_times = []
            homomorphic_result_times = []

            receipts = []

            for index in range(1, voter_count + 1):
                voter_id = "BENCH{:04d}".format(index)
                pin = "{:04d}".format((1000 + index) % 10000)
                voter_hash = storage.hash_voter_id(voter_id)

                start = time.perf_counter()
                authenticated = storage.authenticate_user(voter_id, pin)
                auth_times.append(time.perf_counter() - start)
                if not authenticated:
                    raise RuntimeError("Authentication failed for {}".format(voter_id))

                token_message = crypto_utils.generate_token_message()
                blinded = crypto_utils.blind_token_message(token_message)
                start = time.perf_counter()
                issue_response = client.post(
                    "/issue_token",
                    json={
                        "election_id": election["id"],
                        "voter_hash": voter_hash,
                        "blinded_token": blinded["blinded_token"],
                    },
                )
                token_times.append(time.perf_counter() - start)
                blind_signature = issue_response.get_json()["blind_signature"]
                token_signature = crypto_utils.unblind_signature(blind_signature, blinded["blind_factor"])

                selected_option = election["options"][(index - 1) % len(election["options"])]
                encrypted_ballot = crypto_utils.encrypt_ballot_payload(
                    {
                        "election_id": election["id"],
                        "selection": selected_option,
                        "nonce": "bench-{}".format(index),
                    }
                )
                homomorphic_ballot = crypto_utils.build_homomorphic_ballot(
                    election["options"],
                    selected_option,
                )
                receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
                start = time.perf_counter()
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
                cast_times.append(time.perf_counter() - start)
                if cast_response.status_code != 201:
                    raise RuntimeError("Cast failed for {}".format(voter_id))
                receipts.append(receipt_hash)

            start = time.perf_counter()
            mine_response = client.get("/mine")
            mine_times.append(time.perf_counter() - start)
            if mine_response.status_code != 200:
                raise RuntimeError("Mining failed")

            for receipt_hash in receipts:
                start = time.perf_counter()
                verify_response = client.get("/verify_receipt/{}".format(receipt_hash))
                verify_times.append(time.perf_counter() - start)
                if verify_response.status_code != 200:
                    raise RuntimeError("Receipt verification failed")

            start = time.perf_counter()
            tally = client.get("/results").get_json()
            tally_time = time.perf_counter() - start
            start = time.perf_counter()
            homomorphic_payload = client.get("/homomorphic_results").get_json()
            homomorphic_result_times.append(time.perf_counter() - start)

            return {
                "mode": "measured",
                "voter_count": voter_count,
                "option_count": option_count,
                "authority_count": authority_count,
                "threshold": threshold,
                "auth_mean": statistics.mean(auth_times),
                "auth_median": statistics.median(auth_times),
                "token_mean": statistics.mean(token_times),
                "token_median": statistics.median(token_times),
                "cast_mean": statistics.mean(cast_times),
                "cast_median": statistics.median(cast_times),
                "verify_mean": statistics.mean(verify_times),
                "verify_median": statistics.median(verify_times),
                "mine_mean": statistics.mean(mine_times),
                "mine_median": statistics.median(mine_times),
                "tally_time": tally_time,
                "homomorphic_results_time": statistics.mean(homomorphic_result_times),
                "homomorphic_results_median": statistics.median(homomorphic_result_times),
                "chain_length": len(service.blockchain.chain),
                "total_ballots": sum(tally.values()),
                "threshold_proof_artifact_count": len(
                    homomorphic_payload.get("threshold", {}).get("proof_artifacts", [])
                ),
            }
        finally:
            Config.TALLY_THRESHOLD = original_threshold
            Config.TALLY_AUTHORITY_COUNT = original_authority_count


def load_existing_results(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return [
        {
            key: float(value) if key not in {
                "chain_length", "total_ballots", "voter_count", "option_count", "authority_count", "threshold"
            } else int(float(value))
            for key, value in row.items()
        }
        for row in rows
    ]


def fit_linear(x_values, y_values):
    mean_x = statistics.mean(x_values)
    mean_y = statistics.mean(y_values)
    numerator = sum((x_value - mean_x) * (y_value - mean_y) for x_value, y_value in zip(x_values, y_values))
    denominator = sum((x_value - mean_x) ** 2 for x_value in x_values)
    slope = numerator / denominator if denominator else 0.0
    intercept = mean_y - (slope * mean_x)
    return intercept, slope


def project_with_floor(scale, intercept, slope, floor_value):
    projected = intercept + (slope * scale)
    return max(floor_value, projected)


def build_projection_rows(base_rows, scales):
    grouped_rows = defaultdict(list)
    for row in base_rows:
        key = (
            int(row.get("option_count", 3)),
            int(row.get("authority_count", 3)),
            int(row.get("threshold", 2)),
        )
        grouped_rows[key].append(row)

    projection_rows = []
    for (option_count, authority_count, threshold), scenario_rows in grouped_rows.items():
        x_values = [row["voter_count"] for row in scenario_rows]
        auth_constant = statistics.mean(row["auth_mean"] for row in scenario_rows)
        token_constant = statistics.mean(row["token_mean"] for row in scenario_rows)
        cast_constant = statistics.mean(row["cast_mean"] for row in scenario_rows)
        verify_constant = statistics.mean(row["verify_mean"] for row in scenario_rows)

        mine_intercept, mine_slope = fit_linear(x_values, [row["mine_mean"] for row in scenario_rows])
        tally_intercept, tally_slope = fit_linear(x_values, [row["tally_time"] for row in scenario_rows])
        homomorphic_intercept, homomorphic_slope = fit_linear(
            x_values,
            [row.get("homomorphic_results_time", row["tally_time"]) for row in scenario_rows],
        )
        tally_floor = statistics.mean(row["tally_time"] for row in scenario_rows)
        homomorphic_floor = statistics.mean(
            row.get("homomorphic_results_time", row["tally_time"]) for row in scenario_rows
        )

        for scale in scales:
            projection_rows.append(
                {
                    "mode": "projected",
                    "voter_count": scale,
                    "option_count": option_count,
                    "authority_count": authority_count,
                    "threshold": threshold,
                    "auth_mean": auth_constant,
                    "auth_median": auth_constant,
                    "token_mean": token_constant,
                    "token_median": token_constant,
                    "cast_mean": cast_constant,
                    "cast_median": cast_constant,
                    "verify_mean": verify_constant,
                    "verify_median": verify_constant,
                    "mine_mean": max(0.0, mine_intercept + (mine_slope * scale)),
                    "mine_median": max(0.0, mine_intercept + (mine_slope * scale)),
                    "tally_time": project_with_floor(scale, tally_intercept, tally_slope, tally_floor),
                    "homomorphic_results_time": project_with_floor(
                        scale,
                        homomorphic_intercept,
                        homomorphic_slope,
                        homomorphic_floor,
                    ),
                    "homomorphic_results_median": project_with_floor(
                        scale,
                        homomorphic_intercept,
                        homomorphic_slope,
                        homomorphic_floor,
                    ),
                    "chain_length": 2,
                    "total_ballots": scale,
                    "threshold_proof_artifact_count": threshold * option_count,
                    "auth_total_estimate": auth_constant * scale,
                    "token_total_estimate": token_constant * scale,
                    "cast_total_estimate": cast_constant * scale,
                    "verify_total_estimate": verify_constant * scale,
                }
            )
    return projection_rows


def write_rows(path, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def build_comparison_rows(base_rows):
    comparison_rows = []
    for row in base_rows:
        threshold_time = float(row.get("homomorphic_results_time", row["tally_time"]))
        baseline_time = float(row["tally_time"])
        absolute_overhead = max(0.0, threshold_time - baseline_time)
        relative_overhead = (threshold_time / baseline_time) if baseline_time else 0.0
        comparison_rows.append(
            {
                "mode": row.get("mode", "measured"),
                "voter_count": int(float(row["voter_count"])),
                "option_count": int(float(row.get("option_count", 3))),
                "authority_count": int(float(row.get("authority_count", 3))),
                "threshold": int(float(row.get("threshold", 2))),
                "baseline_results_time": baseline_time,
                "threshold_results_time": threshold_time,
                "absolute_overhead": absolute_overhead,
                "relative_overhead": relative_overhead,
                "threshold_proof_artifact_count": int(float(row.get("threshold_proof_artifact_count", 0))),
            }
        )
    return comparison_rows


def parse_args():
    parser = argparse.ArgumentParser(description="Run measured benchmarks or build projected benchmark tables.")
    parser.add_argument(
        "--mode",
        choices=["measure", "project"],
        default="measure",
        help="measure = run actual local benchmark; project = estimate larger scales from measured baseline",
    )
    parser.add_argument(
        "--scales",
        nargs="*",
        type=int,
        help="Optional custom scale list.",
    )
    parser.add_argument(
        "--option-counts",
        nargs="*",
        type=int,
        default=None,
        help="Optional option counts to benchmark.",
    )
    parser.add_argument(
        "--authority-configs",
        nargs="*",
        default=None,
        help="Optional threshold:authority pairs, for example 2:3 3:5",
    )
    parser.add_argument(
        "--repeats",
        type=int,
        default=REPEATS,
        help="Number of repeated runs per scenario.",
    )
    parser.add_argument(
        "--input",
        default=BENCHMARK_OUTPUT_PATH,
        help="Input CSV for projection mode.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output CSV path.",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.mode == "project":
        scales = args.scales or DEFAULT_PROJECTION_SCALES
        base_rows = load_existing_results(args.input)
        output_rows = build_projection_rows(base_rows, scales)
        output_path = args.output or PROJECTION_OUTPUT_PATH
        write_rows(output_path, output_rows)
        write_rows(COMPARISON_OUTPUT_PATH, build_comparison_rows(output_rows))
        print("Projected benchmark results written to {}".format(output_path))
        for row in output_rows:
            print(row)
        return

    scales = args.scales or SCALES
    option_counts = args.option_counts or OPTION_COUNTS
    authority_configs = AUTHORITY_CONFIGS
    if args.authority_configs:
        authority_configs = []
        for raw_config in args.authority_configs:
            threshold_raw, authority_count_raw = raw_config.split(":", 1)
            authority_configs.append((int(threshold_raw), int(authority_count_raw)))

    output_rows = []
    for threshold, authority_count in authority_configs:
        for option_count in option_counts:
            for scale in scales:
                runs = [
                    benchmark_once(
                        scale,
                        option_count=option_count,
                        authority_count=authority_count,
                        threshold=threshold,
                    )
                    for _ in range(args.repeats)
                ]
                output_rows.append(
                    {
                        "mode": "measured",
                        "voter_count": scale,
                        "option_count": option_count,
                        "authority_count": authority_count,
                        "threshold": threshold,
                        "auth_mean": statistics.mean(run["auth_mean"] for run in runs),
                        "auth_median": statistics.mean(run["auth_median"] for run in runs),
                        "token_mean": statistics.mean(run["token_mean"] for run in runs),
                        "token_median": statistics.mean(run["token_median"] for run in runs),
                        "cast_mean": statistics.mean(run["cast_mean"] for run in runs),
                        "cast_median": statistics.mean(run["cast_median"] for run in runs),
                        "verify_mean": statistics.mean(run["verify_mean"] for run in runs),
                        "verify_median": statistics.mean(run["verify_median"] for run in runs),
                        "mine_mean": statistics.mean(run["mine_mean"] for run in runs),
                        "mine_median": statistics.mean(run["mine_median"] for run in runs),
                        "tally_time": statistics.mean(run["tally_time"] for run in runs),
                        "homomorphic_results_time": statistics.mean(run["homomorphic_results_time"] for run in runs),
                        "homomorphic_results_median": statistics.mean(
                            run["homomorphic_results_median"] for run in runs
                        ),
                        "chain_length": statistics.mean(run["chain_length"] for run in runs),
                        "total_ballots": statistics.mean(run["total_ballots"] for run in runs),
                        "threshold_proof_artifact_count": statistics.mean(
                            run["threshold_proof_artifact_count"] for run in runs
                        ),
                    }
                )

    output_path = args.output or BENCHMARK_OUTPUT_PATH
    write_rows(output_path, output_rows)
    write_rows(COMPARISON_OUTPUT_PATH, build_comparison_rows(output_rows))

    print("Benchmark results written to {}".format(output_path))
    print("Comparison benchmark results written to {}".format(COMPARISON_OUTPUT_PATH))
    for row in output_rows:
        print(row)


if __name__ == "__main__":
    main()
