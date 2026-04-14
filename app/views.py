import csv
from datetime import UTC, datetime
import json
import math
import os
import secrets

import requests
from flask import render_template, redirect, request, session, url_for
from flask import flash
from app import app
import crypto_utils
from logging_config import setup_logging
import storage

CONNECTED_SERVICE_ADDRESS = app.config["CONNECTED_SERVICE_ADDRESS"]

posts = []
REQUEST_TIMEOUT = app.config["REQUEST_TIMEOUT"]
logger = setup_logging("web")
BENCHMARK_RESULTS_PATH = os.path.join(app.root_path, "..", "benchmarks", "output", "benchmark_results.csv")
BENCHMARK_COMPARISON_PATH = os.path.join(app.root_path, "..", "benchmarks", "output", "benchmark_comparison.csv")
BENCHMARK_PROJECTION_PATH = os.path.join(app.root_path, "..", "benchmarks", "output", "benchmark_projection.csv")
SECURITY_PROPERTY_STATUS = [
    {"name": "Eligibility", "status": "Strong", "note": "Registry, PIN auth, role gate, token issuance"},
    {"name": "Uniqueness", "status": "Strong", "note": "One token per voter and spend tracking"},
    {"name": "Privacy", "status": "Partial", "note": "Blind token and encrypted ballot, but timing metadata remains"},
    {"name": "Integrity", "status": "Strong", "note": "Receipt hash, PoW chain, confirmation tracking"},
    {"name": "Verifiability", "status": "Moderate", "note": "Receipt lookup, bulletin board, homomorphic tally"},
    {"name": "Coercion Resistance", "status": "Weak", "note": "Not formally implemented in the prototype"},
]
THREAT_MODEL_CARDS = [
    {"name": "Replay", "mitigation": "Token fingerprint uniqueness and spend registry"},
    {"name": "Double vote", "mitigation": "Single token issuance and ballot uniqueness constraints"},
    {"name": "Ballot tampering", "mitigation": "Receipt mismatch detection and chain validation"},
    {"name": "Deanonymization", "mitigation": "Blind token separation and encrypted ballot payloads"},
    {"name": "Node failure", "mitigation": "Persistence, peer sync and public validity checks"},
]
MISSING_PROTOCOLS = [
    {
        "name": "Coercion Resistance",
        "status": "Missing",
        "why": "The voter still lacks a formal anti-coercion or revoting protocol.",
    },
    {
        "name": "Receipt-Freeness",
        "status": "Missing",
        "why": "Receipt hashes help verification, but they are not a formal receipt-freeness construction.",
    },
    {
        "name": "Independent Threshold Authorities",
        "status": "Partial",
        "why": "Threshold reconstruction exists, but authorities are not yet deployed as separate operational services.",
    },
    {
        "name": "Formal ZKP Stack",
        "status": "Partial",
        "why": "Ballot-validity proofs exist, but the system does not yet implement a full end-to-end zero-knowledge proof framework.",
    },
    {
        "name": "Byzantine-Grade Consensus",
        "status": "Missing",
        "why": "The blockchain layer remains simplified and is not a production BFT consensus protocol.",
    },
    {
        "name": "Mix-Net Anonymity Layer",
        "status": "Missing",
        "why": "The current design does not include a mix-net or equivalent anonymity shuffling stage.",
    },
]
VULNERABILITY_SURFACE = [
    {
        "name": "Timing Correlation",
        "severity": "Moderate",
        "note": "An observer with infrastructure access may still correlate login, token issuance and ballot submission times.",
    },
    {
        "name": "Co-Located Authorities",
        "severity": "Moderate",
        "note": "Threshold authorities are logically separated, but still live in one prototype environment.",
    },
    {
        "name": "Server-Side Trust",
        "severity": "Moderate",
        "note": "Ballot payload decryption and orchestration still rely on application-server integrity.",
    },
    {
        "name": "Simplified Network Consensus",
        "severity": "Moderate",
        "note": "The node layer validates blocks, but does not provide full Byzantine-resilient distributed agreement.",
    },
    {
        "name": "No National-Scale HA",
        "severity": "Low/Moderate",
        "note": "Availability mechanisms remain prototype-grade and are not engineered for large public infrastructure.",
    },
]
ARCHITECTURE_STAGES = [
    {
        "name": "Web Client",
        "role": "Authentication and protocol orchestration",
        "details": "Handles login, issues blinded token requests, submits encrypted ballots and stores receipt hashes.",
    },
    {
        "name": "Token Authority",
        "role": "Blind signature issuance",
        "details": "Signs blinded token material so eligibility is checked without exposing the final ballot identity link.",
    },
    {
        "name": "Blockchain Node",
        "role": "Encrypted ballot intake and mining",
        "details": "Validates ballot structure, records ciphertexts and receipts, then appends mined blocks to the chain.",
    },
    {
        "name": "Public Verification",
        "role": "Bulletin board and tally",
        "details": "Exposes receipt inclusion, bulletin board records and homomorphic tally outputs for external inspection.",
    },
]

DEFENSE_CHECKLIST = [
    {
        "step": "1. Open Presentation",
        "screen": "/presentation",
        "talking_point": "Briefly state the topic, the goal of the system, and that blockchain is combined with cryptographic protocols rather than used alone.",
    },
    {
        "step": "2. Show Protocol Flow",
        "screen": "/",
        "talking_point": "Explain authentication, blind token issuance, encrypted ballot casting, and why identity is separated from the ballot phase.",
    },
    {
        "step": "3. Show Verification",
        "screen": "/verify_vote",
        "talking_point": "Explain individual verifiability through receipt hash and how a voter checks that the ballot was recorded.",
    },
    {
        "step": "4. Show Research Dashboard",
        "screen": "/research",
        "talking_point": "Explain homomorphic tally, threshold authority evidence, public ballot proofs, and the measured benchmark overhead.",
    },
    {
        "step": "5. Show Security Model if asked",
        "screen": "/security_model",
        "talking_point": "Use this page to answer questions about guarantees, residual risks, missing protocols, and scalability limits.",
    },
]

SECURITY_STATUS_SCORES = {
    "Strong": 90,
    "Moderate": 65,
    "Partial": 50,
    "Weak": 25,
    "Missing": 0,
}

VULNERABILITY_SEVERITY_SCORES = {
    "Low": 25,
    "Low/Moderate": 40,
    "Moderate": 60,
    "High": 85,
}

SECURITY_TARGET_PROFILE = [
    {"name": "Security", "current": 72, "target": 92},
    {"name": "Privacy", "current": 50, "target": 88},
    {"name": "Verifiability", "current": 65, "target": 93},
    {"name": "Scalability", "current": 58, "target": 78},
]

PRODUCTION_GAPS = [
    {
        "name": "Independent authorities",
        "note": "Threshold authorities are still co-located in one prototype environment rather than operated as separate services.",
    },
    {
        "name": "Formal anti-coercion layer",
        "note": "Coercion resistance and receipt-freeness are not implemented as production-grade cryptographic protocols.",
    },
    {
        "name": "Full proof stack",
        "note": "Ballot proofs exist, but the system does not yet provide a complete end-to-end ZKP framework for all phases.",
    },
    {
        "name": "Production consensus and availability",
        "note": "The blockchain and deployment model remain prototype-grade rather than BFT and high-availability public infrastructure.",
    },
]

EXPERIMENT_SCALE_TABLE = [
    {
        "scale": "5 voters",
        "purpose": "Baseline protocol sanity check",
        "method": "Measured",
        "interpretation": "Confirms correctness of the end-to-end prototype flow and low-scale timing behavior.",
    },
    {
        "scale": "10 voters",
        "purpose": "Stable small-scale run",
        "method": "Measured",
        "interpretation": "Representative small-scale prototype performance with real cryptographic and tally overhead.",
    },
    {
        "scale": "25 voters",
        "purpose": "Upper measured prototype scale",
        "method": "Measured",
        "interpretation": "Shows the visibility of threshold and proof-bearing overhead before larger-scale stress behavior appears.",
    },
    {
        "scale": "1,000 voters",
        "purpose": "Stress point",
        "method": "Partial real execution",
        "interpretation": "Demonstrates that the Python prototype becomes computationally heavy and should not be presented as production throughput.",
    },
    {
        "scale": "10,000+ voters",
        "purpose": "Scalability discussion",
        "method": "Projected",
        "interpretation": "Used only for trend discussion, not as direct proof of production-scale performance.",
    },
]


def list_security_profiles():
    profiles = []
    for profile_key, profile in storage.SECURITY_PROFILES.items():
        profiles.append(
            {
                "profile_key": profile_key,
                **profile,
            }
        )
    return profiles


def _require_login():
    voter_id = session.get("voter_id")
    if not voter_id:
        return None
    return {
        "voter_id": voter_id,
        "role": session.get("role", "voter")
    }


def _safe_get_json(url, timeout=REQUEST_TIMEOUT):
    try:
        response = requests.get(url, timeout=timeout)
        if response.status_code == 200:
            return response.json()
    except (requests.RequestException, ValueError):
        return None
    return None


def fetch_results():
    results = _safe_get_json("{}/results".format(CONNECTED_SERVICE_ADDRESS))
    return results if isinstance(results, dict) else {}


def fetch_homomorphic_results():
    results = _safe_get_json("{}/homomorphic_results".format(CONNECTED_SERVICE_ADDRESS))
    if isinstance(results, dict):
        return results
    return {"totals": {}, "ballot_count": 0, "aggregated_ciphertexts": []}


def fetch_bulletin_board():
    results = _safe_get_json("{}/bulletin_board".format(CONNECTED_SERVICE_ADDRESS))
    if isinstance(results, dict):
        return results
    return {"items": [], "valid_chain": False, "length": 0}


def fetch_integrity_status():
    results = _safe_get_json("{}/integrity_status".format(CONNECTED_SERVICE_ADDRESS))
    if isinstance(results, dict):
        return results
    return {
        "chain_valid": False,
        "chain_length": 0,
        "ballot_view_consistent": False,
        "ballot_view_repaired": False,
        "pending_transaction_count": 0,
        "confirmed_encrypted_ballot_count": 0,
        "error": "Integrity status unavailable",
    }


def fetch_result_consistency():
    results = _safe_get_json("{}/result_consistency".format(CONNECTED_SERVICE_ADDRESS))
    if isinstance(results, dict):
        return results
    return {
        "election_id": None,
        "election_name": None,
        "chain_counts": {},
        "derived_view_counts": {},
        "counts_match": False,
    }


def trigger_rebuild_state_from_chain():
    try:
        response = requests.post(
            "{}/rebuild_state_from_chain".format(CONNECTED_SERVICE_ADDRESS),
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return {"ok": False, "error": str(exc)}

    try:
        payload = response.json()
    except ValueError:
        payload = {"error": response.text}

    if response.status_code == 200:
        return {"ok": True, "payload": payload}
    return {"ok": False, "error": payload.get("error", "Rebuild failed")}


def build_ballot_proof_summary(bulletin_board):
    items = bulletin_board.get("items", []) if isinstance(bulletin_board, dict) else []
    summary = {
        "ballot_count": 0,
        "ballots_with_proofs": 0,
        "valid_ballots": 0,
        "bit_proof_count": 0,
        "sum_proof_count": 0,
    }

    for item in items:
        homomorphic_ballot = item.get("homomorphic_ballot")
        if not homomorphic_ballot:
            continue
        if isinstance(homomorphic_ballot, str):
            try:
                homomorphic_ballot = json.loads(homomorphic_ballot)
            except ValueError:
                continue
        if not isinstance(homomorphic_ballot, dict):
            continue

        summary["ballot_count"] += 1
        ciphertexts = homomorphic_ballot.get("ciphertexts", [])
        validity_proofs = homomorphic_ballot.get("validity_proofs", [])
        sum_proof = homomorphic_ballot.get("sum_proof")
        has_complete_proofs = (
            isinstance(ciphertexts, list) and
            isinstance(validity_proofs, list) and
            len(ciphertexts) == len(validity_proofs) and
            isinstance(sum_proof, dict)
        )
        if not has_complete_proofs:
            continue

        summary["ballots_with_proofs"] += 1
        summary["bit_proof_count"] += len(validity_proofs)
        summary["sum_proof_count"] += 1

        bit_valid = all(
            crypto_utils.verify_ciphertext_bit_proof(ciphertext, proof)
            for ciphertext, proof in zip(ciphertexts, validity_proofs)
        )
        sum_valid = crypto_utils.verify_ballot_sum_proof(ciphertexts, sum_proof)
        if bit_valid and sum_valid:
            summary["valid_ballots"] += 1

    return summary


def load_benchmark_snapshot():
    if not os.path.exists(BENCHMARK_RESULTS_PATH):
        return []

    with open(BENCHMARK_RESULTS_PATH, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    snapshot = []
    for row in rows:
        snapshot.append(
            {
                "voter_count": int(float(row["voter_count"])),
                "auth_mean": float(row["auth_mean"]),
                "token_mean": float(row["token_mean"]),
                "cast_mean": float(row["cast_mean"]),
                "verify_mean": float(row["verify_mean"]),
                "mine_mean": float(row["mine_mean"]),
                "tally_time": float(row["tally_time"]),
            }
        )
    return snapshot


def load_benchmark_comparison_snapshot():
    if not os.path.exists(BENCHMARK_COMPARISON_PATH):
        return []

    with open(BENCHMARK_COMPARISON_PATH, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    snapshot = []
    for row in rows:
        snapshot.append(
            {
                "voter_count": int(float(row["voter_count"])),
                "baseline_results_time": float(row["baseline_results_time"]),
                "threshold_results_time": float(row["threshold_results_time"]),
                "absolute_overhead": float(row["absolute_overhead"]),
                "relative_overhead": float(row["relative_overhead"]),
                "threshold_proof_artifact_count": int(float(row["threshold_proof_artifact_count"])),
            }
        )
    return snapshot


def load_benchmark_projection_snapshot():
    if not os.path.exists(BENCHMARK_PROJECTION_PATH):
        return []

    with open(BENCHMARK_PROJECTION_PATH, "r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    snapshot = []
    for row in rows:
        snapshot.append(
            {
                "mode": row["mode"],
                "voter_count": int(float(row["voter_count"])),
                "auth_mean": float(row["auth_mean"]),
                "token_mean": float(row["token_mean"]),
                "cast_mean": float(row["cast_mean"]),
                "verify_mean": float(row["verify_mean"]),
                "mine_mean": float(row["mine_mean"]),
                "tally_time": float(row["tally_time"]),
                "homomorphic_results_time": float(row.get("homomorphic_results_time", row["tally_time"])),
                "chain_length": int(float(row["chain_length"])),
                "total_ballots": int(float(row["total_ballots"])),
                "auth_total_estimate": float(row["auth_total_estimate"]),
                "token_total_estimate": float(row["token_total_estimate"]),
                "cast_total_estimate": float(row["cast_total_estimate"]),
                "verify_total_estimate": float(row["verify_total_estimate"]),
            }
        )
    return snapshot


def build_benchmark_comparison_summary(rows):
    if not rows:
        return None

    max_row = max(rows, key=lambda row: row["voter_count"])
    mean_relative_overhead = sum(row["relative_overhead"] for row in rows) / len(rows)
    mean_absolute_overhead = sum(row["absolute_overhead"] for row in rows) / len(rows)
    return {
        "largest_scale": max_row["voter_count"],
        "largest_baseline_time": max_row["baseline_results_time"],
        "largest_threshold_time": max_row["threshold_results_time"],
        "largest_relative_overhead": max_row["relative_overhead"],
        "mean_relative_overhead": mean_relative_overhead,
        "mean_absolute_overhead": mean_absolute_overhead,
        "proof_artifact_count": max_row["threshold_proof_artifact_count"],
    }


def build_scalability_summary(rows):
    if not rows:
        return None

    largest = max(rows, key=lambda row: row["voter_count"])
    return {
        "largest_scale": largest["voter_count"],
        "mine_mean": largest["mine_mean"],
        "tally_time": largest["tally_time"],
        "homomorphic_results_time": largest.get("homomorphic_results_time", largest["tally_time"]),
        "cast_total_estimate": largest["cast_total_estimate"],
        "verify_total_estimate": largest["verify_total_estimate"],
    }


def build_performance_honesty_summary(benchmark_rows, comparison_summary, projection_rows):
    measured_scales = [row["voter_count"] for row in benchmark_rows] if benchmark_rows else []
    projected_scales = [row["voter_count"] for row in projection_rows] if projection_rows else []
    small_signal_tally = False
    if benchmark_rows:
        measured_tallies = [row["tally_time"] for row in benchmark_rows]
        small_signal_tally = max(measured_tallies) < 0.005
    return {
        "measured_min_scale": min(measured_scales) if measured_scales else None,
        "measured_max_scale": max(measured_scales) if measured_scales else None,
        "projected_min_scale": min(projected_scales) if projected_scales else None,
        "projected_max_scale": max(projected_scales) if projected_scales else None,
        "threshold_overhead_note": (
            "Threshold tally overhead is measured on the current prototype implementation and includes signed proof publication."
            if comparison_summary else None
        ),
        "projection_note": (
            "Projection values are model-based extrapolations from the measured prototype baseline, not direct executions at that scale."
            if projection_rows else None
        ),
        "tally_projection_note": (
            "Tally projection is lower-confidence than mining projection because the measured tally baseline is sub-millisecond and relatively noisy."
            if projection_rows and small_signal_tally else None
        ),
        "homomorphic_projection_note": (
            "Threshold/homomorphic results time is usually the more informative projection for this prototype because it includes signed proof-bearing tally publication."
            if projection_rows else None
        ),
    }


def build_security_property_chart_rows(properties):
    rows = []
    for item in properties:
        rows.append(
            {
                **item,
                "score": SECURITY_STATUS_SCORES.get(item["status"], 0),
            }
        )
    return rows


def build_missing_protocol_chart_rows(protocols):
    rows = []
    for item in protocols:
        rows.append(
            {
                **item,
                "gap_score": 100 if item["status"] == "Missing" else 55,
            }
        )
    return rows


def build_vulnerability_chart_rows(vulnerabilities):
    rows = []
    for item in vulnerabilities:
        rows.append(
            {
                **item,
                "severity_score": VULNERABILITY_SEVERITY_SCORES.get(item["severity"], 50),
            }
        )
    return rows


def build_security_model_overview(properties, protocols, vulnerabilities, comparison_summary, scalability_summary):
    strong_properties = sum(1 for item in properties if item["status"] == "Strong")
    partial_or_better = sum(1 for item in properties if item["status"] in {"Strong", "Moderate", "Partial"})
    missing_protocols = sum(1 for item in protocols if item["status"] == "Missing")
    moderate_plus_risks = sum(1 for item in vulnerabilities if item["severity"] in {"Moderate", "High"})
    overview = {
        "strong_properties": strong_properties,
        "covered_properties": partial_or_better,
        "total_properties": len(properties),
        "missing_protocols": missing_protocols,
        "total_protocol_gaps": len(protocols),
        "moderate_plus_risks": moderate_plus_risks,
        "total_risks": len(vulnerabilities),
    }
    if comparison_summary:
        overview["largest_overhead"] = comparison_summary["largest_relative_overhead"]
        overview["largest_overhead_scale"] = comparison_summary["largest_scale"]
    if scalability_summary:
        overview["largest_scale"] = scalability_summary["largest_scale"]
        overview["projected_tally_time"] = scalability_summary["tally_time"]
    return overview


def build_scalability_chart_rows(rows):
    if not rows:
        return []

    max_mine = max(row["mine_mean"] for row in rows) or 1.0
    max_tally = max(row["tally_time"] for row in rows) or 1.0
    max_homomorphic = max(row.get("homomorphic_results_time", row["tally_time"]) for row in rows) or 1.0
    chart_rows = []
    for row in rows:
        chart_rows.append(
            {
                **row,
                "mine_ratio": (row["mine_mean"] / max_mine) * 100,
                "tally_ratio": (row["tally_time"] / max_tally) * 100,
                "homomorphic_ratio": (
                    row.get("homomorphic_results_time", row["tally_time"]) / max_homomorphic
                ) * 100,
            }
        )
    return chart_rows


def build_security_overview_radar():
    metrics = [
        ("Security", 72),
        ("Privacy", 50),
        ("Verifiability", 65),
        ("Scalability", 58),
    ]
    cx = 110
    cy = 110
    radius = 78
    points = []
    label_points = []
    ring_paths = []

    for ring_ratio in (0.25, 0.5, 0.75, 1.0):
        ring = []
        for index in range(len(metrics)):
            angle = -90 + (360 / len(metrics)) * index
            radians = math.radians(angle)
            x = cx + (radius * ring_ratio) * math.cos(radians)
            y = cy + (radius * ring_ratio) * math.sin(radians)
            ring.append("{:.2f},{:.2f}".format(x, y))
        ring_paths.append(" ".join(ring))

    for index, (label, value) in enumerate(metrics):
        angle = -90 + (360 / len(metrics)) * index
        radians = math.radians(angle)
        point_radius = radius * (value / 100)
        x = cx + point_radius * math.cos(radians)
        y = cy + point_radius * math.sin(radians)
        points.append("{:.2f},{:.2f}".format(x, y))
        lx = cx + (radius + 24) * math.cos(radians)
        ly = cy + (radius + 24) * math.sin(radians)
        label_points.append({"label": label, "x": lx, "y": ly, "value": value})

    return {
        "width": 220,
        "height": 220,
        "center_x": cx,
        "center_y": cy,
        "radius": radius,
        "rings": ring_paths,
        "polygon": " ".join(points),
        "labels": label_points,
    }


def build_security_target_comparison():
    rows = []
    for item in SECURITY_TARGET_PROFILE:
        rows.append(
            {
                **item,
                "gap": max(item["target"] - item["current"], 0),
            }
        )
    return rows


def build_benchmark_visuals(rows):
    if not rows:
        return []

    max_cast = max(row["cast_mean"] for row in rows) or 1.0
    max_mine = max(row["mine_mean"] for row in rows) or 1.0
    visuals = []
    for row in rows:
        visuals.append(
            {
                **row,
                "cast_ratio": row["cast_mean"] / max_cast,
                "mine_ratio": row["mine_mean"] / max_mine,
            }
        )
    return visuals


def build_sparkline(values, width=240, height=72):
    if not values:
        return ""

    if len(values) == 1:
        return "0,{:.2f} {},{:.2f}".format(height / 2, width, height / 2)

    min_value = min(values)
    max_value = max(values)
    spread = max_value - min_value or 1.0
    points = []
    for index, value in enumerate(values):
        x_value = (width / (len(values) - 1)) * index
        y_ratio = (value - min_value) / spread
        y_value = height - (y_ratio * (height - 8)) - 4
        points.append("{:.2f},{:.2f}".format(x_value, y_value))
    return " ".join(points)


def _get_or_create_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


def _validate_csrf_token(token):
    return bool(token) and token == session.get("csrf_token")


def _get_vote_verification(signature=None):
    vote_signature = (signature or session.get("last_vote_signature") or "").strip()
    if not vote_signature:
        return None

    ballot = storage.get_ballot_by_signature(vote_signature)
    if not ballot:
        return {
            "vote_signature": vote_signature,
            "found": False
        }

    return {
        "vote_signature": vote_signature,
        "found": True,
        "status": ballot["status"],
        "selection": ballot["selection"],
        "voter_hash": ballot["voter_hash"],
        "election_name": ballot["election_name"],
        "tx_timestamp": ballot["tx_timestamp"],
        "block_index": ballot["block_index"],
        "block_hash": ballot["block_hash"],
    }


def _get_receipt_verification(receipt_hash=None):
    receipt_hash = (receipt_hash or session.get("last_receipt_hash") or "").strip()
    if not receipt_hash or not storage.is_valid_vote_signature(receipt_hash):
        return None

    ballot = storage.get_ballot_by_receipt(receipt_hash)
    if not ballot:
        return {
            "receipt_hash": receipt_hash,
            "found": False
        }

    return {
        "receipt_hash": receipt_hash,
        "found": True,
        "status": ballot["status"],
        "election_name": ballot["election_name"],
        "selection": ballot["selection"],
        "tx_timestamp": ballot["tx_timestamp"],
        "block_index": ballot["block_index"],
        "token_fingerprint": ballot["token_fingerprint"],
    }


def _issue_anonymous_token_for_session(voter_hash, election_id):
    token_message = crypto_utils.generate_token_message()
    blinded = crypto_utils.blind_token_message(token_message)
    response = requests.post(
        "{}/issue_token".format(CONNECTED_SERVICE_ADDRESS),
        json={
            "election_id": election_id,
            "voter_hash": voter_hash,
            "blinded_token": blinded["blinded_token"],
        },
        headers={"Content-type": "application/json"},
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code != 201:
        try:
            error_message = response.json().get("error", response.text)
        except ValueError:
            error_message = response.text
        raise RuntimeError(error_message)

    blind_signature = response.json()["blind_signature"]
    token_signature = crypto_utils.unblind_signature(blind_signature, blinded["blind_factor"])
    if not crypto_utils.verify_token_signature(token_message, token_signature):
        raise RuntimeError("Token verification failed after unblinding")

    token_package = {
        "token_message": token_message,
        "token_signature": token_signature,
        "token_fingerprint": crypto_utils.token_fingerprint(token_message),
        "election_id": election_id,
    }
    session["anonymous_token"] = token_package
    return token_package


def _validate_vote_choice(party, active_election):
    return bool(party) and party in active_election["options"]


def _parse_election_options(raw_text):
    options = [option.strip() for option in (raw_text or "").splitlines()]
    options = [option for option in options if option]
    deduplicated = []
    seen = set()
    for option in options:
        key = option.lower()
        if key in seen:
            continue
        seen.add(key)
        deduplicated.append(option)
    return deduplicated


def _validate_election_form(election_name, security_profile, election_options, status=None):
    if len(election_name) < 5:
        return 'Election name is too short.'
    if security_profile not in storage.SECURITY_PROFILES:
        return 'Invalid security profile.'
    if len(election_options) < 2:
        return 'At least two election options are required.'
    if status is not None and status not in {"draft", "active", "closed"}:
        return 'Invalid election status.'
    return None


@app.before_request
def enforce_https():
    if app.config["FORCE_HTTPS"] and not app.config.get("TESTING") and not request.is_secure:
        secure_url = request.url.replace("http://", "https://", 1)
        return redirect(secure_url, code=301)


@app.context_processor
def inject_template_globals():
    return {
        "csrf_token": _get_or_create_csrf_token(),
        "current_role": session.get("role"),
        "current_voter_id": session.get("voter_id"),
        "presentation_mode": False,
    }


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Simple login to authenticate the voter before voting."""
    if request.method == 'POST':
        if not _validate_csrf_token(request.form.get("csrf_token")):
            flash('Invalid or missing CSRF token.', 'error')
            return redirect(url_for('login'))

        voter_id = (request.form.get('voter_id') or "").strip().upper()
        pin = (request.form.get('pin') or "").strip()

        if not storage.is_valid_voter_id(voter_id) or not storage.is_valid_pin(pin):
            flash('Voter ID and PIN are required.', 'error')
            return redirect(url_for('login'))

        client_key = "{}:{}".format(request.remote_addr or "unknown", voter_id)
        limit_status = storage.get_rate_limit_status("login", client_key)
        if limit_status and (limit_status.get("blocked_until") or 0) > datetime.now().timestamp():
            flash('Too many login attempts. Try again later.', 'error')
            return redirect(url_for('login'))

        user = storage.authenticate_user(voter_id, pin)
        if not user:
            storage.register_rate_limit_attempt(
                "login",
                client_key,
                app.config["LOGIN_RATE_LIMIT_ATTEMPTS"],
                app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"],
                app.config["LOGIN_RATE_LIMIT_BLOCK_SECONDS"]
            )
            storage.record_audit_event(
                "login_failed",
                "user",
                actor_id=voter_id,
                details={"reason": "invalid_credentials", "remote_addr": request.remote_addr}
            )
            logger.warning("Failed login for voter_id=%s", voter_id)
            flash('Invalid Voter ID or PIN.', 'error')
            return redirect(url_for('login'))

        storage.reset_rate_limit("login", client_key)
        session.clear()
        session.permanent = True
        session['voter_id'] = voter_id
        session['role'] = user["role"]
        storage.record_audit_event(
            "login_success",
            "user",
            actor_id=voter_id,
            details={"role": user["role"], "remote_addr": request.remote_addr}
        )
        logger.info("Successful login for voter_id=%s role=%s", voter_id, user["role"])
        flash('Logged in as {} ({})'.format(voter_id, user["role"]), 'success')
        return redirect(url_for('index'))

    return render_template(
        'login.html',
        show_demo_credentials=app.config["SHOW_DEMO_CREDENTIALS"],
        security_profiles=list_security_profiles(),
    )


@app.route('/logout')
def logout():
    voter_id = session.pop('voter_id', None)
    role = session.pop('role', None)
    session.pop("last_vote_signature", None)
    if voter_id:
        storage.record_audit_event("logout", "user", actor_id=voter_id, details={"role": role})
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))


def fetch_posts():
    """Fetch the chain from a blockchain node, parse the data and store it locally."""
    chain = _safe_get_json("{}/chain".format(CONNECTED_SERVICE_ADDRESS))
    if not chain:
        return

    content = []

    for block in chain.get("chain", []):
        for tx in block.get("transactions", []):
            tx["index"] = block.get("index")
            tx["hash"] = block.get("previous_hash")
            tx["party"] = tx.get("party") or tx.get("selection") or "Encrypted ballot"
            tx["voter_id"] = (
                tx.get("voter_id")
                or tx.get("voter_hash")
                or tx.get("token_fingerprint")
                or ""
            )
            # We may display a short “signature” to help with auditability.
            tx["vote_signature"] = tx.get("vote_signature") or tx.get("receipt_hash") or ""
            content.append(tx)

    # Also include any pending (unmined) transactions so the UI can show a vote is in flight.
    pending = _safe_get_json("{}/pending_tx".format(CONNECTED_SERVICE_ADDRESS))
    if isinstance(pending, list):
        for tx in pending:
            if not isinstance(tx, dict):
                continue
            tx["index"] = None
            tx["hash"] = tx.get("previous_hash") or ""
            tx["party"] = tx.get("party") or tx.get("selection") or "Encrypted ballot"
            tx["voter_id"] = (
                tx.get("voter_id")
                or tx.get("voter_hash")
                or tx.get("token_fingerprint")
                or ""
            )
            tx["vote_signature"] = tx.get("vote_signature") or tx.get("receipt_hash") or ""
            tx["_status"] = "pending"
            content.append(tx)

    global posts
    posts = sorted(content, key=lambda k: k.get('timestamp', 0), reverse=True)


def fetch_chain_status():
    """Fetch the node's chain validity status."""
    validate_address = "{}/validate".format(CONNECTED_SERVICE_ADDRESS)
    response_data = _safe_get_json(validate_address, timeout=3)
    if response_data:
        return response_data
    return {"valid": False, "length": 0, "difficulty": 0, "error": "Node unavailable"}


def _recent_posts(limit=6):
    return posts[:limit]


def _restore_latest_receipt_hash(voter_id, election_id=None):
    voter_hash = storage.hash_voter_id(voter_id)
    receipt_hash = storage.get_latest_receipt_hash_for_voter(voter_hash, election_id=election_id)
    if receipt_hash:
        session["last_receipt_hash"] = receipt_hash
    return receipt_hash


@app.route('/')
def index():
    # Require authentication for voting
    user = _require_login()
    if not user:
        return redirect(url_for('login'))
    voter_id = user["voter_id"]
    role = user["role"]

    fetch_posts()
    active_election = storage.get_active_election()
    if not active_election:
        flash('No active election configured.', 'error')
        return render_template(
            'index.html',
            title='E-voting system using Blockchain and python',
            posts=posts,
            recent_posts=[],
            vote_results={},
            homomorphic_results={"totals": {}, "ballot_count": 0, "aggregated_ciphertexts": []},
            chain_status=fetch_chain_status(),
            node_address=CONNECTED_SERVICE_ADDRESS,
            readable_time=timestamp_to_string,
            political_parties=[],
            voter_id=voter_id,
            role=role,
            has_voted=False,
            token_ready=False,
            current_voter_hash='',
            active_election=None,
            latest_receipt_hash=session.get("last_receipt_hash"),
            security_profiles=list_security_profiles(),
        )

    latest_receipt_hash = session.get("last_receipt_hash")
    if role == "voter" and not latest_receipt_hash:
        latest_receipt_hash = _restore_latest_receipt_hash(voter_id, election_id=active_election["id"])

    # Determine whether this voter has already cast a vote (based on their hashed ID).
    voter_hash = storage.hash_voter_id(voter_id)
    has_voted = storage.ballot_exists(active_election["id"], voter_hash) if role == "voter" else False

    vote_results = fetch_results()
    homomorphic_results = fetch_homomorphic_results()
    chain_status = fetch_chain_status()
    verification = _get_vote_verification()
    receipt_verification = _get_receipt_verification(latest_receipt_hash)
    token_ready = bool(session.get("anonymous_token")) if role == "voter" and not has_voted else False

    return render_template('index.html',
                           title='E-voting system '
                                 'using Blockchain and python',
                           posts=posts,
                           recent_posts=_recent_posts(),
                           vote_results=vote_results,
                           homomorphic_results=homomorphic_results,
                           chain_status=chain_status,
                           node_address=CONNECTED_SERVICE_ADDRESS,
                           readable_time=timestamp_to_string,
                           political_parties=active_election["options"],
                           voter_id=voter_id,
                           role=role,
                           has_voted=has_voted,
                           token_ready=token_ready,
                           current_voter_hash=voter_hash,
                           active_election=active_election,
                           verification=verification,
                           receipt_verification=receipt_verification,
                           latest_receipt_hash=latest_receipt_hash,
                           security_profiles=list_security_profiles())


@app.route('/issue_token', methods=['POST'])
def issue_token_for_vote():
    user = _require_login()
    if not user:
        flash('You must be logged in to request an anonymous token.', 'error')
        return redirect(url_for('login'))

    if user["role"] != "voter":
        flash('Only voters can request anonymous voting tokens.', 'error')
        return redirect('/')

    if not _validate_csrf_token(request.form.get("csrf_token")):
        flash('Invalid or missing CSRF token.', 'error')
        return redirect('/')

    active_election = storage.get_active_election()
    if not active_election:
        flash('No active election configured.', 'error')
        return redirect('/')

    voter_hash = storage.hash_voter_id(user["voter_id"])
    if storage.ballot_exists(active_election["id"], voter_hash):
        flash('You have already cast a ballot.', 'error')
        return redirect('/')

    try:
        token_package = _issue_anonymous_token_for_session(voter_hash, active_election["id"])
    except Exception as exc:
        flash('Anonymous token request failed: {}'.format(exc), 'error')
        return redirect('/')

    storage.record_audit_event(
        "anonymous_token_requested_web",
        "user",
        actor_id=user["voter_id"],
        election_id=active_election["id"],
        details={"token_fingerprint": token_package["token_fingerprint"]}
    )
    flash('Anonymous voting token issued. You can now cast an encrypted ballot.', 'success')
    return redirect('/')


@app.route('/submit', methods=['POST'])
def submit_textarea():
    """
    Endpoint to create a new transaction via our application.
    """
    user = _require_login()
    if not user:
        flash('You must be logged in to vote.', 'error')
        return redirect(url_for('login'))
    voter_id = user["voter_id"]
    role = user["role"]

    if role != "voter":
        flash('Only users with voter role can submit a ballot.', 'error')
        return redirect('/')

    if not _validate_csrf_token(request.form.get("csrf_token")):
        flash('Invalid or missing CSRF token.', 'error')
        return redirect('/')

    active_election = storage.get_active_election()
    if not active_election:
        flash('No active election configured.', 'error')
        return redirect('/')

    party = (request.form.get("party") or "").strip()
    if not _validate_vote_choice(party, active_election):
        flash('Invalid election option.', 'error')
        return redirect('/')

    token_package = session.get("anonymous_token")
    if not token_package or token_package.get("election_id") != active_election["id"]:
        flash('Anonymous token required. Request a token before casting a ballot.', 'error')
        return redirect('/')

    vote_limit_key = "{}:{}".format(request.remote_addr or "unknown", voter_id)
    vote_limit_status = storage.register_rate_limit_attempt(
        "vote_submit",
        vote_limit_key,
        app.config["VOTE_RATE_LIMIT_ATTEMPTS"],
        app.config["VOTE_RATE_LIMIT_WINDOW_SECONDS"],
        app.config["VOTE_RATE_LIMIT_BLOCK_SECONDS"]
    )
    if not vote_limit_status["allowed"]:
        storage.record_audit_event(
            "vote_rate_limited",
            "user",
            actor_id=voter_id,
            election_id=active_election["id"],
            details={"retry_after": vote_limit_status["retry_after"], "remote_addr": request.remote_addr}
        )
        flash('Too many vote submissions. Try again later.', 'error')
        return redirect('/')

    # Send only the hashed voter identity to the node (no plain voter_id in transit).
    voter_hash = storage.hash_voter_id(voter_id)
    encrypted_ballot = crypto_utils.encrypt_ballot_payload({
        "election_id": active_election["id"],
        "selection": party,
        "nonce": secrets.token_hex(8),
        "issued_at": datetime.now(UTC).isoformat(),
    })
    homomorphic_ballot = crypto_utils.build_homomorphic_ballot(active_election["options"], party)
    receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)

    post_object = {
        "election_id": active_election["id"],
        "token_message": token_package["token_message"],
        "token_signature": token_package["token_signature"],
        "encrypted_ballot": encrypted_ballot,
        "receipt_hash": receipt_hash,
        "homomorphic_ballot": homomorphic_ballot,
    }

    # Submit a transaction
    new_tx_address = "{}/cast_ballot".format(CONNECTED_SERVICE_ADDRESS)
    try:
        response = requests.post(new_tx_address,
                                 json=post_object,
                                 headers={'Content-type': 'application/json'},
                                 timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        flash('Vote failed: {}'.format(exc), 'error')
        return redirect('/')

    if response.status_code != 201:
        try:
            error_message = response.json().get("error", response.text)
        except ValueError:
            error_message = response.text
        flash('Vote failed: ' + error_message, 'error')
        return redirect('/')

    try:
        resp_data = response.json()
        session["last_receipt_hash"] = resp_data.get("receipt_hash")
        session.pop("anonymous_token", None)
        storage.record_audit_event(
            "encrypted_vote_requested",
            "user",
            actor_id=voter_id,
            election_id=active_election["id"],
            details={
                "party": party,
                "receipt_hash": resp_data.get("receipt_hash"),
                "token_fingerprint": resp_data.get("token_fingerprint"),
                "remote_addr": request.remote_addr
            }
        )
        storage.mark_voter_token_spent(active_election["id"], voter_hash, resp_data.get("receipt_hash"))
        logger.info("Vote submitted voter_id=%s election_id=%s", voter_id, active_election["id"])
        flash(
            'Encrypted ballot accepted. Your receipt hash: {}'.format(resp_data.get("receipt_hash")),
            'success'
        )
    except Exception:
        flash('Voted to '+party+' successfully!', 'success')

    # Optionally request the node to mine the new vote so it appears in the chain quickly.
    mine_address = "{}/mine".format(CONNECTED_SERVICE_ADDRESS)
    try:
        mine_resp = requests.get(mine_address, timeout=10)
        if mine_resp.status_code == 200:
            try:
                mine_data = mine_resp.json()
                flash(mine_data.get("message", "Mining completed."), 'info')
            except ValueError:
                flash(mine_resp.text, 'info')
    except requests.RequestException as e:
        flash('Mining request failed: {}'.format(e), 'error')

    return redirect('/')


@app.route('/verify_vote', methods=['GET', 'POST'])
def verify_vote():
    user = _require_login()
    if not user:
        flash('You must be logged in to verify a vote.', 'error')
        return redirect(url_for('login'))
    voter_id = user["voter_id"]

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            flash('Invalid or missing CSRF token.', 'error')
            return redirect(url_for('verify_vote'))

        receipt_hash = request.form.get("vote_signature", "").strip()
        if not storage.is_valid_vote_signature(receipt_hash):
            flash('Receipt hash is required for verification.', 'error')
            return redirect(url_for('verify_vote'))

        session["last_receipt_hash"] = receipt_hash
        verification = _get_receipt_verification(receipt_hash)
        if verification and verification.get("found"):
            flash('Receipt verification completed.', 'success')
        else:
            flash('Receipt hash not found.', 'error')
        return redirect(url_for('verify_vote'))

    receipt_hash = session.get("last_receipt_hash")
    if not receipt_hash and user["role"] == "voter":
        active_election = storage.get_active_election()
        election_id = active_election["id"] if active_election else None
        receipt_hash = _restore_latest_receipt_hash(voter_id, election_id=election_id)

    verification = _get_receipt_verification(receipt_hash)
    bulletin_board = fetch_bulletin_board()
    return render_template(
        'verify_vote.html',
        title='Verify Receipt',
        voter_id=voter_id,
        role=user["role"],
        verification=verification,
        latest_receipt_hash=receipt_hash,
        bulletin_board_count=len(bulletin_board.get("items", [])),
        readable_time=timestamp_to_string,
    )


@app.route('/research')
def research_dashboard():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))

    fetch_posts()
    active_election = storage.get_active_election()
    chain_status = fetch_chain_status()
    homomorphic_results = fetch_homomorphic_results()
    bulletin_board = fetch_bulletin_board()
    proof_summary = build_ballot_proof_summary(bulletin_board)
    benchmark_rows = load_benchmark_snapshot()
    comparison_rows = load_benchmark_comparison_snapshot()
    comparison_summary = build_benchmark_comparison_summary(comparison_rows)
    projection_rows = load_benchmark_projection_snapshot()
    scalability_summary = build_scalability_summary(projection_rows)
    events = []
    if user["role"] in {"admin", "auditor"}:
        events = storage.list_audit_events(limit=min(10, app.config["AUDIT_EVENT_LIMIT"]))

    cast_values = [row["cast_mean"] for row in benchmark_rows]
    mine_values = [row["mine_mean"] for row in benchmark_rows]
    verify_values = [row["verify_mean"] for row in benchmark_rows]

    return render_template(
        'research.html',
        title='Research Dashboard',
        voter_id=user["voter_id"],
        role=user["role"],
        active_election=active_election,
        chain_status=chain_status,
        homomorphic_results=homomorphic_results,
        bulletin_board=bulletin_board,
        proof_summary=proof_summary,
        benchmark_rows=benchmark_rows,
        comparison_rows=comparison_rows,
        comparison_summary=comparison_summary,
        projection_rows=projection_rows,
        scalability_summary=scalability_summary,
        benchmark_visuals=build_benchmark_visuals(benchmark_rows),
        cast_sparkline=build_sparkline(cast_values),
        mine_sparkline=build_sparkline(mine_values),
        verify_sparkline=build_sparkline(verify_values),
        security_properties=SECURITY_PROPERTY_STATUS,
        threat_cards=THREAT_MODEL_CARDS,
        recent_posts=_recent_posts(),
        events=events,
        readable_time=timestamp_to_string,
        node_address=CONNECTED_SERVICE_ADDRESS,
    )


@app.route('/security_model')
def security_model():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))

    benchmark_rows = load_benchmark_snapshot()
    comparison_rows = load_benchmark_comparison_snapshot()
    comparison_summary = build_benchmark_comparison_summary(comparison_rows)
    projection_rows = load_benchmark_projection_snapshot()
    scalability_summary = build_scalability_summary(projection_rows)

    return render_template(
        'security_model.html',
        title='Security Model',
        voter_id=user["voter_id"],
        role=user["role"],
        security_properties=SECURITY_PROPERTY_STATUS,
        security_property_chart_rows=build_security_property_chart_rows(SECURITY_PROPERTY_STATUS),
        threat_cards=THREAT_MODEL_CARDS,
        missing_protocols=MISSING_PROTOCOLS,
        missing_protocol_chart_rows=build_missing_protocol_chart_rows(MISSING_PROTOCOLS),
        vulnerability_surface=VULNERABILITY_SURFACE,
        vulnerability_chart_rows=build_vulnerability_chart_rows(VULNERABILITY_SURFACE),
        benchmark_rows=benchmark_rows,
        comparison_summary=comparison_summary,
        projection_rows=projection_rows,
        scalability_summary=scalability_summary,
        scalability_chart_rows=build_scalability_chart_rows(projection_rows),
        security_overview_radar=build_security_overview_radar(),
        security_target_comparison=build_security_target_comparison(),
        production_gaps=PRODUCTION_GAPS,
        experiment_scale_table=EXPERIMENT_SCALE_TABLE,
        performance_honesty_summary=build_performance_honesty_summary(
            benchmark_rows,
            comparison_summary,
            projection_rows,
        ),
        security_model_overview=build_security_model_overview(
            SECURITY_PROPERTY_STATUS,
            MISSING_PROTOCOLS,
            VULNERABILITY_SURFACE,
            comparison_summary,
            scalability_summary,
        ),
    )


@app.route('/defense_demo')
def defense_demo():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))

    active_election = storage.get_active_election()
    chain_status = fetch_chain_status()
    homomorphic_results = fetch_homomorphic_results()
    bulletin_board = fetch_bulletin_board()
    proof_summary = build_ballot_proof_summary(bulletin_board)
    benchmark_rows = load_benchmark_snapshot()
    comparison_summary = build_benchmark_comparison_summary(load_benchmark_comparison_snapshot())

    return render_template(
        'defense_demo.html',
        title='Defense Demo',
        voter_id=user["voter_id"],
        role=user["role"],
        active_election=active_election,
        chain_status=chain_status,
        homomorphic_results=homomorphic_results,
        bulletin_board=bulletin_board,
        proof_summary=proof_summary,
        benchmark_rows=benchmark_rows,
        comparison_summary=comparison_summary,
        architecture_stages=ARCHITECTURE_STAGES,
        defense_checklist=DEFENSE_CHECKLIST,
        security_properties=SECURITY_PROPERTY_STATUS,
        threat_cards=THREAT_MODEL_CARDS,
        presentation_mode=False,
    )


@app.route('/presentation')
def presentation_mode():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))

    active_election = storage.get_active_election()
    chain_status = fetch_chain_status()
    homomorphic_results = fetch_homomorphic_results()
    bulletin_board = fetch_bulletin_board()
    proof_summary = build_ballot_proof_summary(bulletin_board)
    benchmark_rows = load_benchmark_snapshot()
    comparison_summary = build_benchmark_comparison_summary(load_benchmark_comparison_snapshot())

    return render_template(
        'defense_demo.html',
        title='Presentation Mode',
        voter_id=user["voter_id"],
        role=user["role"],
        active_election=active_election,
        chain_status=chain_status,
        homomorphic_results=homomorphic_results,
        bulletin_board=bulletin_board,
        proof_summary=proof_summary,
        benchmark_rows=benchmark_rows,
        comparison_summary=comparison_summary,
        architecture_stages=ARCHITECTURE_STAGES,
        defense_checklist=DEFENSE_CHECKLIST,
        security_properties=SECURITY_PROPERTY_STATUS,
        threat_cards=THREAT_MODEL_CARDS,
        presentation_mode=True,
    )


@app.route('/audit')
@app.route('/audit', methods=['GET', 'POST'])
def audit_dashboard():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))
    if user["role"] not in {"admin", "auditor"}:
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            flash('Invalid or missing CSRF token.', 'error')
            return redirect(url_for('audit_dashboard'))

        action = (request.form.get("action") or "create").strip()
        if action == "rebuild_state":
            rebuild_result = trigger_rebuild_state_from_chain()
            if rebuild_result["ok"]:
                storage.record_audit_event(
                    "confirmed_ballot_view_rebuild_requested",
                    user["role"],
                    actor_id=user["voter_id"],
                    details=rebuild_result["payload"],
                )
                flash('Confirmed ballot view rebuilt from blockchain.', 'success')
            else:
                flash('State rebuild failed: {}'.format(rebuild_result["error"]), 'error')
            return redirect(url_for('audit_dashboard'))

        if user["role"] != "admin":
            flash('Only admin can create elections.', 'error')
            return redirect(url_for('audit_dashboard'))

        if action == "set_status":
            election_id_raw = (request.form.get("election_id") or "").strip()
            status = (request.form.get("status") or "").strip()
            if not election_id_raw.isdigit():
                flash('Invalid election identifier.', 'error')
                return redirect(url_for('audit_dashboard'))
            election_id = int(election_id_raw)
            election = storage.get_election(election_id)
            if not election:
                flash('Election not found.', 'error')
                return redirect(url_for('audit_dashboard'))
            try:
                storage.update_election_status(election_id, status)
            except ValueError:
                flash('Invalid election status.', 'error')
                return redirect(url_for('audit_dashboard'))
            storage.record_audit_event(
                "election_status_changed",
                "admin",
                actor_id=user["voter_id"],
                election_id=election_id,
                details={"status": status},
            )
            flash('Election status updated.', 'success')
            return redirect(url_for('audit_dashboard'))

        election_name = (request.form.get("election_name") or "").strip()
        security_profile = (request.form.get("security_profile") or "").strip()
        election_options = _parse_election_options(request.form.get("election_options"))
        status = (request.form.get("status") or "draft").strip()
        validation_error = _validate_election_form(
            election_name,
            security_profile,
            election_options,
            status=status,
        )
        if validation_error:
            flash(validation_error, 'error')
            return redirect(url_for('audit_dashboard'))

        election_id = storage.create_election(
            election_name,
            election_options,
            security_profile,
            status=status,
        )
        storage.record_audit_event(
            "election_created",
            "admin",
            actor_id=user["voter_id"],
            election_id=election_id,
            details={
                "security_profile": security_profile,
                "option_count": len(election_options),
                "status": status,
            },
        )
        flash('Election created successfully.', 'success')
        return redirect(url_for('audit_dashboard'))

    selected_event_type = (request.args.get("event_type") or "").strip()
    selected_actor_type = (request.args.get("actor_type") or "").strip()
    limit_raw = (request.args.get("limit") or "").strip()
    allowed_limits = [10, 25, 50, 100]
    selected_limit = int(limit_raw) if limit_raw.isdigit() and int(limit_raw) in allowed_limits else app.config["AUDIT_EVENT_LIMIT"]

    base_events = storage.list_audit_events(limit=max(allowed_limits + [app.config["AUDIT_EVENT_LIMIT"]]))
    available_event_types = sorted({event["event_type"] for event in base_events})
    available_actor_types = sorted({event["actor_type"] for event in base_events})

    if selected_event_type and selected_event_type not in available_event_types:
        selected_event_type = ""
    if selected_actor_type and selected_actor_type not in available_actor_types:
        selected_actor_type = ""

    events = storage.list_audit_events(
        limit=selected_limit,
        event_type=selected_event_type or None,
        actor_type=selected_actor_type or None,
    )
    integrity_status = fetch_integrity_status()
    result_consistency = fetch_result_consistency()
    return render_template(
        'audit.html',
        title='Audit Dashboard',
        events=events,
        integrity_status=integrity_status,
        result_consistency=result_consistency,
        elections=storage.list_elections(),
        security_profiles=list_security_profiles(),
        selected_event_type=selected_event_type,
        selected_actor_type=selected_actor_type,
        selected_limit=selected_limit,
        allowed_limits=allowed_limits,
        available_event_types=available_event_types,
        available_actor_types=available_actor_types,
        readable_time=timestamp_to_string,
        voter_id=user["voter_id"],
        role=user["role"]
    )


@app.route('/admin/elections', methods=['GET', 'POST'])
def election_designer():
    user = _require_login()
    if not user:
        return redirect(url_for('login'))
    if user["role"] != "admin":
        flash('Access denied.', 'error')
        return redirect(url_for('index'))

    if request.method == "POST":
        if not _validate_csrf_token(request.form.get("csrf_token")):
            flash('Invalid or missing CSRF token.', 'error')
            return redirect(url_for('election_designer'))

        action = (request.form.get("action") or "create").strip()
        if action == "set_status":
            election_id_raw = (request.form.get("election_id") or "").strip()
            status = (request.form.get("status") or "").strip()
            if not election_id_raw.isdigit():
                flash('Invalid election identifier.', 'error')
                return redirect(url_for('election_designer'))
            election_id = int(election_id_raw)
            election = storage.get_election(election_id)
            if not election:
                flash('Election not found.', 'error')
                return redirect(url_for('election_designer'))
            try:
                storage.update_election_status(election_id, status)
            except ValueError:
                flash('Invalid election status.', 'error')
                return redirect(url_for('election_designer'))
            storage.record_audit_event(
                "election_status_changed",
                "admin",
                actor_id=user["voter_id"],
                election_id=election_id,
                details={"status": status, "source": "election_designer"},
            )
            flash('Election status updated.', 'success')
            return redirect(url_for('election_designer', edit_id=election_id))

        election_name = (request.form.get("election_name") or "").strip()
        security_profile = (request.form.get("security_profile") or "").strip()
        election_options = _parse_election_options(request.form.get("election_options"))
        validation_error = _validate_election_form(
            election_name,
            security_profile,
            election_options,
        )
        if validation_error:
            flash(validation_error, 'error')
            return redirect(url_for('election_designer'))

        if action == "edit":
            election_id_raw = (request.form.get("election_id") or "").strip()
            if not election_id_raw.isdigit():
                flash('Invalid election identifier.', 'error')
                return redirect(url_for('election_designer'))
            election_id = int(election_id_raw)
            updated = storage.update_election_details(
                election_id,
                election_name,
                election_options,
                security_profile,
            )
            if not updated:
                flash('Only draft elections can be edited.', 'error')
                return redirect(url_for('election_designer', edit_id=election_id))
            storage.record_audit_event(
                "election_updated",
                "admin",
                actor_id=user["voter_id"],
                election_id=election_id,
                details={
                    "security_profile": security_profile,
                    "option_count": len(election_options),
                },
            )
            flash('Election updated successfully.', 'success')
            return redirect(url_for('election_designer', edit_id=election_id))

        status = (request.form.get("status") or "draft").strip()
        if status not in {"draft", "active", "closed"}:
            flash('Invalid election status.', 'error')
            return redirect(url_for('election_designer'))
        election_id = storage.create_election(
            election_name,
            election_options,
            security_profile,
            status=status,
        )
        storage.record_audit_event(
            "election_created",
            "admin",
            actor_id=user["voter_id"],
            election_id=election_id,
            details={
                "security_profile": security_profile,
                "option_count": len(election_options),
                "status": status,
                "source": "election_designer",
            },
        )
        flash('Election created successfully.', 'success')
        return redirect(url_for('election_designer', edit_id=election_id))

    elections = storage.list_elections()
    edit_id = request.args.get("edit_id", "").strip()
    selected_election = None
    if edit_id.isdigit():
        selected_election = storage.get_election(int(edit_id))
    if selected_election is None:
        selected_election = next((e for e in elections if e["status"] == "draft"), None)

    return render_template(
        'election_designer.html',
        title='Election Designer',
        voter_id=user["voter_id"],
        role=user["role"],
        elections=elections,
        selected_election=selected_election,
        security_profiles=list_security_profiles(),
    )


def timestamp_to_string(epoch_time):
    return datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M')
