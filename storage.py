import hashlib
import json
import os
import re
import sqlite3
import threading
import time

import crypto_utils
from config import Config


_db_lock = threading.Lock()
_database_path = Config.DATABASE_PATH

SECURITY_PROFILES = {
    "basic": {
        "label": "Basic",
        "description": "For low-risk local voting where integrity matters more than advanced anonymity.",
        "plain_language_rationale": "Choose this when you need a simple, fast, and transparent vote for a low-risk event, and advanced anonymity is not the main requirement.",
        "confidentiality_level": "low",
        "security_score": 40,
        "privacy_score": 25,
        "transparency_score": 45,
        "scalability_score": 90,
        "protocol_mode": "Simple authenticated ballot recording",
        "enabled_features": [
            "login and role control",
            "blockchain audit trail",
            "basic audit logging",
            "integrity validation",
        ],
        "recommended_use_cases": [
            "student polls and classroom voting",
            "small local committees",
            "low-risk internal community decisions",
        ],
        "not_recommended_for": [
            "high-stakes public elections",
            "events requiring strong anonymity guarantees",
            "scenarios demanding threshold or proof-bearing tally",
        ],
        "missing_features": [
            "anonymous token",
            "threshold tally",
            "public ballot proofs",
            "advanced anonymity",
        ],
        "role_expectations": {
            "voter": "Logs in and submits a ballot with minimal overhead.",
            "admin": "Monitors integrity and keeps the event operational.",
            "auditor": "Checks basic audit trail and chain validity.",
        },
    },
    "standard": {
        "label": "Standard",
        "description": "For institutional voting with anonymous authorization and encrypted ballots.",
        "plain_language_rationale": "Choose this when you need a balanced profile: stronger privacy than a simple poll, but better scalability and lower complexity than the high-assurance mode.",
        "confidentiality_level": "medium",
        "security_score": 68,
        "privacy_score": 62,
        "transparency_score": 70,
        "scalability_score": 74,
        "protocol_mode": "Anonymous authorization with encrypted ballot",
        "enabled_features": [
            "anonymous token",
            "encrypted ballot",
            "receipt verification",
            "bulletin board",
        ],
        "recommended_use_cases": [
            "university governance votes",
            "professional association elections",
            "corporate or institutional ballots",
        ],
        "not_recommended_for": [
            "national or state-level elections",
            "events requiring strong threshold trust reduction",
            "scenarios demanding the strongest public proof layer",
        ],
        "missing_features": [
            "threshold tally",
            "independent authorities",
            "full proof stack",
        ],
        "role_expectations": {
            "voter": "Receives an anonymous token before casting an encrypted ballot.",
            "admin": "Configures privacy/transparency trade-offs for institutional use.",
            "auditor": "Verifies receipts, bulletin board entries, and audit log consistency.",
        },
    },
    "high_assurance": {
        "label": "High Assurance",
        "description": "For high-stakes elections with proof-bearing ballots and threshold-supported tally publication.",
        "plain_language_rationale": "Choose this for important elections where privacy, public verifiability, and stronger trust reduction matter more than raw throughput.",
        "confidentiality_level": "high",
        "security_score": 86,
        "privacy_score": 84,
        "transparency_score": 88,
        "scalability_score": 56,
        "protocol_mode": "Proof-bearing encrypted ballots with threshold-supported tally",
        "enabled_features": [
            "blind-signature authorization",
            "encrypted ballots",
            "ballot validity proofs",
            "homomorphic tally",
            "threshold tally evidence",
        ],
        "recommended_use_cases": [
            "municipal elections",
            "high-stakes academic governance",
            "critical board or senate elections",
        ],
        "not_recommended_for": [
            "the highest-risk national deployments",
            "full coercion-resistant voting requirements",
            "scenarios requiring independent multi-authority operation end-to-end",
        ],
        "missing_features": [
            "independent threshold authorities",
            "coercion resistance",
            "full end-to-end ZKP stack",
        ],
        "role_expectations": {
            "voter": "Uses blind authorization and submits a proof-bearing encrypted ballot.",
            "admin": "Chooses a high-trust profile for critical elections and manages lifecycle carefully.",
            "auditor": "Checks ballot proof counts, threshold authority artifacts, and public tally consistency.",
        },
    },
    "maximum_protection": {
        "label": "Maximum Protection",
        "description": "For national-scale or state-level elections requiring the strongest trust and privacy model.",
        "plain_language_rationale": "Choose this only for the highest-risk scenarios that justify the heaviest protocol stack and the strongest operational controls.",
        "confidentiality_level": "very_high",
        "security_score": 96,
        "privacy_score": 94,
        "transparency_score": 93,
        "scalability_score": 38,
        "protocol_mode": "Maximum trust reduction and strongest privacy model",
        "enabled_features": [
            "all high assurance controls",
            "independent threshold authorities",
            "formal ZKP stack",
            "stronger operational separation",
        ],
        "recommended_use_cases": [
            "national-scale elections",
            "state-level referendums",
            "highest-trust public decision processes",
        ],
        "not_recommended_for": [
            "lightweight low-risk voting where simplicity is preferred",
            "resource-constrained rapid deployments",
            "the current prototype without further implementation work",
        ],
        "missing_features": [
            "not fully implemented in the current prototype",
        ],
        "role_expectations": {
            "voter": "Would vote under the strongest privacy and verification guarantees.",
            "admin": "Would orchestrate the most demanding deployment and operational policy.",
            "auditor": "Would inspect a full public-verifiability and distributed-trust workflow.",
        },
    },
}


def _normalize_security_profile(profile_name):
    if profile_name in SECURITY_PROFILES:
        return profile_name
    return "high_assurance"


def build_security_profile_metadata(profile_name):
    normalized = _normalize_security_profile(profile_name)
    return {
        "profile_key": normalized,
        **SECURITY_PROFILES[normalized],
    }


def set_database_path(path):
    global _database_path
    _database_path = path


def get_database_path():
    return _database_path


def get_connection():
    os.makedirs(os.path.dirname(get_database_path()), exist_ok=True)
    connection = sqlite3.connect(get_database_path())
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _read_json_file(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def hash_pin(pin, salt=None):
    salt = salt or os.urandom(16).hex()
    digest = hashlib.scrypt(
        pin.encode("utf-8"),
        salt=bytes.fromhex(salt),
        n=2 ** 14,
        r=8,
        p=1,
        dklen=64
    ).hex()
    return "scrypt$16384$8$1${}${}".format(salt, digest)


def verify_pin(pin, stored_hash):
    if not stored_hash:
        return False

    if stored_hash.startswith("scrypt$"):
        parts = stored_hash.split("$", 5)
        if len(parts) != 6:
            return False

        _, n_value, r_value, p_value, salt, digest_value = parts
        digest_value = digest_value.lstrip("$")
        digest = hashlib.scrypt(
            pin.encode("utf-8"),
            salt=bytes.fromhex(salt),
            n=int(n_value),
            r=int(r_value),
            p=int(p_value),
            dklen=64
        ).hex()
        return digest_value == digest and stored_hash in {
            "scrypt${}${}${}${}${}".format(
                n_value,
                r_value,
                p_value,
                salt,
                digest
            ),
            "scrypt${}${}${}${}$${}".format(
                n_value,
                r_value,
                p_value,
                salt,
                digest
            ),
        }

    if "$" in stored_hash:
        salt, _ = stored_hash.split("$", 1)
        legacy_hash = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode("utf-8"),
            bytes.fromhex(salt),
            100000
        ).hex()
        return stored_hash == "{}${}".format(salt, legacy_hash)

    return False


def hash_voter_id(voter_id):
    return hashlib.sha256(voter_id.encode("utf-8")).hexdigest()


def initialize_storage(reset=False):
    with _db_lock:
        if reset and os.path.exists(get_database_path()):
            os.remove(get_database_path())

        connection = get_connection()
        try:
            _create_schema(connection)
            _migrate_schema(connection)
            _seed_voters(connection)
            _seed_elections(connection)
            connection.commit()
        finally:
            connection.close()


def _column_exists(connection, table_name, column_name):
    rows = connection.execute("PRAGMA table_info({})".format(table_name)).fetchall()
    return any(row["name"] == column_name for row in rows)


def _migrate_schema(connection):
    if not _column_exists(connection, "voters", "role"):
        connection.execute("ALTER TABLE voters ADD COLUMN role TEXT NOT NULL DEFAULT 'voter'")
    if not _column_exists(connection, "elections", "security_profile"):
        connection.execute("ALTER TABLE elections ADD COLUMN security_profile TEXT NOT NULL DEFAULT 'high_assurance'")
    if not _column_exists(connection, "elections", "confidentiality_level"):
        connection.execute("ALTER TABLE elections ADD COLUMN confidentiality_level TEXT NOT NULL DEFAULT 'high'")
    if not _column_exists(connection, "elections", "security_score"):
        connection.execute("ALTER TABLE elections ADD COLUMN security_score INTEGER NOT NULL DEFAULT 86")
    if not _column_exists(connection, "elections", "privacy_score"):
        connection.execute("ALTER TABLE elections ADD COLUMN privacy_score INTEGER NOT NULL DEFAULT 84")
    if not _column_exists(connection, "elections", "transparency_score"):
        connection.execute("ALTER TABLE elections ADD COLUMN transparency_score INTEGER NOT NULL DEFAULT 88")
    if not _column_exists(connection, "elections", "scalability_score"):
        connection.execute("ALTER TABLE elections ADD COLUMN scalability_score INTEGER NOT NULL DEFAULT 56")

    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS rate_limits (
            action TEXT NOT NULL,
            actor_key TEXT NOT NULL,
            attempt_count INTEGER NOT NULL,
            window_started REAL NOT NULL,
            blocked_until REAL NULL,
            updated_at REAL NOT NULL,
            PRIMARY KEY (action, actor_key)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS anonymous_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            voter_hash TEXT NOT NULL,
            issued_at REAL NOT NULL,
            spent_at REAL NULL,
            receipt_hash TEXT NULL,
            UNIQUE(election_id, voter_hash),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
        """
    )
    connection.execute(
        """
        UPDATE elections
        SET
            security_profile = COALESCE(NULLIF(security_profile, ''), 'high_assurance'),
            confidentiality_level = COALESCE(NULLIF(confidentiality_level, ''), 'high'),
            security_score = CASE WHEN security_score IS NULL OR security_score = 0 THEN 86 ELSE security_score END,
            privacy_score = CASE WHEN privacy_score IS NULL OR privacy_score = 0 THEN 84 ELSE privacy_score END,
            transparency_score = CASE WHEN transparency_score IS NULL OR transparency_score = 0 THEN 88 ELSE transparency_score END,
            scalability_score = CASE WHEN scalability_score IS NULL OR scalability_score = 0 THEN 56 ELSE scalability_score END
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS token_spends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            token_fingerprint TEXT NOT NULL UNIQUE,
            receipt_hash TEXT NOT NULL UNIQUE,
            spent_at REAL NOT NULL,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS tally_authorities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            authority_name TEXT NOT NULL UNIQUE,
            authority_index INTEGER NOT NULL UNIQUE,
            share_value_hex TEXT NOT NULL,
            public_commitment_hex TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        )
        """
    )
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS tally_partial_decryptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            tally_fingerprint TEXT NOT NULL,
            option_index INTEGER NOT NULL,
            authority_name TEXT NOT NULL,
            partial_value_hex TEXT NOT NULL,
            signature_hex TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            UNIQUE(election_id, tally_fingerprint, option_index, authority_name),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        )
        """
    )
    if not _column_exists(connection, "tally_partial_decryptions", "signature_hex"):
        connection.execute(
            "ALTER TABLE tally_partial_decryptions ADD COLUMN signature_hex TEXT NOT NULL DEFAULT ''"
        )

    for column_name, definition in [
        ("receipt_hash", "TEXT"),
        ("encrypted_ballot", "TEXT"),
        ("token_fingerprint", "TEXT"),
        ("token_signature", "TEXT"),
        ("homomorphic_ballot", "TEXT"),
    ]:
        if not _column_exists(connection, "ballots", column_name):
            connection.execute(
                "ALTER TABLE ballots ADD COLUMN {} {}".format(column_name, definition)
            )


def _create_schema(connection):
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS voters (
            voter_id TEXT PRIMARY KEY,
            pin_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'voter',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS elections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            status TEXT NOT NULL,
            security_profile TEXT NOT NULL DEFAULT 'high_assurance',
            confidentiality_level TEXT NOT NULL DEFAULT 'high',
            security_score INTEGER NOT NULL DEFAULT 86,
            privacy_score INTEGER NOT NULL DEFAULT 84,
            transparency_score INTEGER NOT NULL DEFAULT 88,
            scalability_score INTEGER NOT NULL DEFAULT 56,
            starts_at TEXT NULL,
            ends_at TEXT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS election_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            option_name TEXT NOT NULL,
            FOREIGN KEY (election_id) REFERENCES elections(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS ballots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            voter_hash TEXT NOT NULL,
            selection TEXT NOT NULL,
            vote_signature TEXT NOT NULL,
            tx_timestamp REAL NOT NULL,
            status TEXT NOT NULL,
            block_index INTEGER NULL,
            block_hash TEXT NULL,
            created_at REAL NOT NULL,
            UNIQUE(election_id, voter_hash),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        );

        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            block_index INTEGER NOT NULL UNIQUE,
            previous_hash TEXT NOT NULL,
            block_hash TEXT NOT NULL UNIQUE,
            nonce INTEGER NOT NULL,
            timestamp REAL NOT NULL,
            transactions_json TEXT NOT NULL,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_type TEXT NOT NULL,
            actor_id TEXT NULL,
            election_id INTEGER NULL,
            details_json TEXT NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY (election_id) REFERENCES elections(id)
        );

        CREATE TABLE IF NOT EXISTS tally_authorities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            authority_name TEXT NOT NULL UNIQUE,
            authority_index INTEGER NOT NULL UNIQUE,
            share_value_hex TEXT NOT NULL,
            public_commitment_hex TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tally_partial_decryptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            election_id INTEGER NOT NULL,
            tally_fingerprint TEXT NOT NULL,
            option_index INTEGER NOT NULL,
            authority_name TEXT NOT NULL,
            partial_value_hex TEXT NOT NULL,
            signature_hex TEXT NOT NULL DEFAULT '',
            created_at REAL NOT NULL,
            UNIQUE(election_id, tally_fingerprint, option_index, authority_name),
            FOREIGN KEY (election_id) REFERENCES elections(id)
        );
        """
    )


def _seed_voters(connection):
    existing = connection.execute("SELECT COUNT(*) FROM voters").fetchone()[0]
    if existing:
        return

    now = time.time()
    voters = _read_json_file(Config.VOTERS_FILE_PATH)
    connection.executemany(
        """
        INSERT INTO voters (voter_id, pin_hash, role, is_active, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [
            (
                voter["voter_id"],
                voter.get("pin_hash") or hash_pin(voter["pin"]),
                voter.get("role", "voter"),
                1 if voter.get("is_active", True) else 0,
                now
            )
            for voter in voters
        ]
    )


def _seed_elections(connection):
    existing = connection.execute("SELECT COUNT(*) FROM elections").fetchone()[0]
    if existing:
        return

    now = time.time()
    elections = _read_json_file(Config.ELECTIONS_FILE_PATH)
    for election in elections:
        profile = build_security_profile_metadata(election.get("security_profile", "high_assurance"))
        cursor = connection.execute(
            """
            INSERT INTO elections (
                name, status, security_profile, confidentiality_level,
                security_score, privacy_score, transparency_score, scalability_score,
                starts_at, ends_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                election["name"],
                election["status"],
                profile["profile_key"],
                profile["confidentiality_level"],
                profile["security_score"],
                profile["privacy_score"],
                profile["transparency_score"],
                profile["scalability_score"],
                election.get("starts_at"),
                election.get("ends_at"),
                now
            )
        )
        election_id = cursor.lastrowid
        connection.executemany(
            """
            INSERT INTO election_options (election_id, option_name)
            VALUES (?, ?)
            """,
            [(election_id, option) for option in election.get("options", [])]
        )


def get_voter(voter_id):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT voter_id, pin_hash, role, is_active, created_at FROM voters WHERE voter_id = ?",
            (voter_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def update_voter_pin_hash(voter_id, pin_hash):
    connection = get_connection()
    try:
        connection.execute(
            "UPDATE voters SET pin_hash = ? WHERE voter_id = ?",
            (pin_hash, voter_id)
        )
        connection.commit()
    finally:
        connection.close()


def authenticate_user(voter_id, pin):
    voter = get_voter(voter_id)
    if not voter or not voter["is_active"]:
        return None

    if not verify_pin(pin, voter["pin_hash"]):
        return None

    if not voter["pin_hash"].startswith("scrypt$"):
        update_voter_pin_hash(voter_id, hash_pin(pin))
        voter["pin_hash"] = get_voter(voter_id)["pin_hash"]

    return voter


def authenticate_voter(voter_id, pin):
    voter = authenticate_user(voter_id, pin)
    return bool(voter and voter["role"] == "voter")


def list_active_voters():
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT voter_id FROM voters WHERE is_active = 1 AND role = 'voter' ORDER BY voter_id"
        ).fetchall()
        return [row["voter_id"] for row in rows]
    finally:
        connection.close()


def get_registered_voter_hashes():
    return {hash_voter_id(voter_id) for voter_id in list_active_voters()}


def get_active_election():
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT
                id, name, status, security_profile, confidentiality_level,
                security_score, privacy_score, transparency_score, scalability_score,
                starts_at, ends_at
            FROM elections
            WHERE status = 'active'
            ORDER BY id DESC
            LIMIT 1
            """
        ).fetchone()
        if not row:
            return None

        election = dict(row)
        option_rows = connection.execute(
            "SELECT option_name FROM election_options WHERE election_id = ? ORDER BY id",
            (election["id"],)
        ).fetchall()
        election["options"] = [option["option_name"] for option in option_rows]
        election["profile"] = build_security_profile_metadata(election["security_profile"])
        return election
    finally:
        connection.close()


def list_elections():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                id, name, status, security_profile, confidentiality_level,
                security_score, privacy_score, transparency_score, scalability_score,
                starts_at, ends_at
            FROM elections
            ORDER BY id DESC
            """
        ).fetchall()
        elections = []
        for row in rows:
            election = dict(row)
            option_rows = connection.execute(
                "SELECT option_name FROM election_options WHERE election_id = ? ORDER BY id",
                (election["id"],)
            ).fetchall()
            election["options"] = [option["option_name"] for option in option_rows]
            election["profile"] = build_security_profile_metadata(election["security_profile"])
            elections.append(election)
        return elections
    finally:
        connection.close()


def create_election(name, options, security_profile, starts_at=None, ends_at=None, status="draft"):
    profile = build_security_profile_metadata(security_profile)
    connection = get_connection()
    try:
        cursor = connection.execute(
            """
            INSERT INTO elections (
                name, status, security_profile, confidentiality_level,
                security_score, privacy_score, transparency_score, scalability_score,
                starts_at, ends_at, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                name,
                status,
                profile["profile_key"],
                profile["confidentiality_level"],
                profile["security_score"],
                profile["privacy_score"],
                profile["transparency_score"],
                profile["scalability_score"],
                starts_at,
                ends_at,
                time.time(),
            ),
        )
        election_id = cursor.lastrowid
        connection.executemany(
            """
            INSERT INTO election_options (election_id, option_name)
            VALUES (?, ?)
            """,
            [(election_id, option) for option in options],
        )
        connection.commit()
        return election_id
    finally:
        connection.close()


def update_election_status(election_id, status):
    if status not in {"draft", "active", "closed"}:
        raise ValueError("Invalid election status")

    connection = get_connection()
    try:
        if status == "active":
            connection.execute("UPDATE elections SET status = 'closed' WHERE status = 'active'")
        connection.execute(
            "UPDATE elections SET status = ? WHERE id = ?",
            (status, election_id),
        )
        connection.commit()
    finally:
        connection.close()


def update_election_details(election_id, name, options, security_profile):
    profile = build_security_profile_metadata(security_profile)
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT status FROM elections WHERE id = ? LIMIT 1",
            (election_id,),
        ).fetchone()
        if not row or row["status"] != "draft":
            return False

        connection.execute(
            """
            UPDATE elections
            SET
                name = ?,
                security_profile = ?,
                confidentiality_level = ?,
                security_score = ?,
                privacy_score = ?,
                transparency_score = ?,
                scalability_score = ?
            WHERE id = ?
            """,
            (
                name,
                profile["profile_key"],
                profile["confidentiality_level"],
                profile["security_score"],
                profile["privacy_score"],
                profile["transparency_score"],
                profile["scalability_score"],
                election_id,
            ),
        )
        connection.execute(
            "DELETE FROM election_options WHERE election_id = ?",
            (election_id,),
        )
        connection.executemany(
            """
            INSERT INTO election_options (election_id, option_name)
            VALUES (?, ?)
            """,
            [(election_id, option) for option in options],
        )
        connection.commit()
        return True
    finally:
        connection.close()


def get_election(election_id):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT
                id, name, status, security_profile, confidentiality_level,
                security_score, privacy_score, transparency_score, scalability_score,
                starts_at, ends_at
            FROM elections
            WHERE id = ?
            LIMIT 1
            """,
            (election_id,),
        ).fetchone()
        if not row:
            return None
        election = dict(row)
        option_rows = connection.execute(
            "SELECT option_name FROM election_options WHERE election_id = ? ORDER BY id",
            (election_id,),
        ).fetchall()
        election["options"] = [option["option_name"] for option in option_rows]
        election["profile"] = build_security_profile_metadata(election["security_profile"])
        return election
    finally:
        connection.close()


def list_users_by_role():
    connection = get_connection()
    try:
        rows = connection.execute(
            "SELECT voter_id, role, is_active FROM voters ORDER BY role, voter_id"
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def is_valid_voter_id(voter_id):
    return bool(re.fullmatch(r"[A-Z0-9]{4,20}", voter_id or ""))


def is_valid_pin(pin):
    return bool(re.fullmatch(r"\d{4,12}", pin or ""))


def is_valid_vote_signature(vote_signature):
    return bool(re.fullmatch(r"[0-9a-f]{64}", vote_signature or ""))


def is_valid_voter_hash(voter_hash):
    return is_valid_vote_signature(voter_hash)


def is_valid_election_option(election_id, option_name):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM election_options
            WHERE election_id = ? AND option_name = ?
            """,
            (election_id, option_name)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def create_ballot(election_id, voter_hash, selection, vote_signature, tx_timestamp, status="pending"):
    connection = get_connection()
    try:
        try:
            connection.execute(
                """
                INSERT INTO ballots (
                    election_id, voter_hash, selection, vote_signature, tx_timestamp,
                    status, block_index, block_hash, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?)
                """,
                (
                    election_id,
                    voter_hash,
                    selection,
                    vote_signature,
                    tx_timestamp,
                    status,
                    time.time()
                )
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    finally:
        connection.close()


def issue_anonymous_token(election_id, voter_hash):
    connection = get_connection()
    try:
        existing = connection.execute(
            """
            SELECT 1 FROM anonymous_tokens
            WHERE election_id = ? AND voter_hash = ?
            LIMIT 1
            """,
            (election_id, voter_hash)
        ).fetchone()
        if existing:
            return False

        connection.execute(
            """
            INSERT INTO anonymous_tokens (election_id, voter_hash, issued_at, spent_at, receipt_hash)
            VALUES (?, ?, ?, NULL, NULL)
            """,
            (election_id, voter_hash, time.time())
        )
        connection.commit()
        return True
    finally:
        connection.close()


def voter_has_token(election_id, voter_hash):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT 1 FROM anonymous_tokens
            WHERE election_id = ? AND voter_hash = ?
            LIMIT 1
            """,
            (election_id, voter_hash)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def mark_voter_token_spent(election_id, voter_hash, receipt_hash):
    connection = get_connection()
    try:
        connection.execute(
            """
            UPDATE anonymous_tokens
            SET spent_at = ?, receipt_hash = ?
            WHERE election_id = ? AND voter_hash = ? AND spent_at IS NULL
            """,
            (time.time(), receipt_hash, election_id, voter_hash)
        )
        connection.commit()
    finally:
        connection.close()


def get_latest_receipt_hash_for_voter(voter_hash, election_id=None):
    connection = get_connection()
    try:
        if election_id is None:
            row = connection.execute(
                """
                SELECT receipt_hash
                FROM anonymous_tokens
                WHERE voter_hash = ? AND receipt_hash IS NOT NULL
                ORDER BY spent_at DESC, issued_at DESC
                LIMIT 1
                """,
                (voter_hash,)
            ).fetchone()
        else:
            row = connection.execute(
                """
                SELECT receipt_hash
                FROM anonymous_tokens
                WHERE election_id = ? AND voter_hash = ? AND receipt_hash IS NOT NULL
                ORDER BY spent_at DESC, issued_at DESC
                LIMIT 1
                """,
                (election_id, voter_hash)
            ).fetchone()
        return row["receipt_hash"] if row else None
    finally:
        connection.close()


def is_token_spent(token_fingerprint):
    connection = get_connection()
    try:
        row = connection.execute(
            "SELECT 1 FROM token_spends WHERE token_fingerprint = ? LIMIT 1",
            (token_fingerprint,)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def spend_token(election_id, token_fingerprint, receipt_hash):
    connection = get_connection()
    try:
        try:
            connection.execute(
                """
                INSERT INTO token_spends (election_id, token_fingerprint, receipt_hash, spent_at)
                VALUES (?, ?, ?, ?)
                """,
                (election_id, token_fingerprint, receipt_hash, time.time())
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    finally:
        connection.close()


def create_encrypted_ballot(
    election_id,
    token_fingerprint,
    encrypted_ballot,
    receipt_hash,
    token_signature,
    tx_timestamp,
    selection,
    homomorphic_ballot=None,
    status="pending"
):
    connection = get_connection()
    try:
        try:
            connection.execute(
                """
                INSERT INTO ballots (
                    election_id, voter_hash, selection, vote_signature, tx_timestamp,
                    status, block_index, block_hash, created_at,
                    receipt_hash, encrypted_ballot, token_fingerprint, token_signature, homomorphic_ballot
                )
                VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?)
                """,
                (
                    election_id,
                    token_fingerprint,
                    selection,
                    receipt_hash,
                    tx_timestamp,
                    status,
                    time.time(),
                    receipt_hash,
                    encrypted_ballot,
                    token_fingerprint,
                    token_signature,
                    homomorphic_ballot,
                )
            )
            connection.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    finally:
        connection.close()


def ballot_exists(election_id, voter_hash):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT 1
            FROM ballots
            WHERE election_id = ? AND voter_hash = ?
            LIMIT 1
            """,
            (election_id, voter_hash)
        ).fetchone()
        return row is not None
    finally:
        connection.close()


def get_pending_ballots():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT election_id, voter_hash, selection, vote_signature, tx_timestamp
            FROM ballots
            WHERE status = 'pending'
            ORDER BY id
            """
        ).fetchall()
        return [
            {
                "election_id": row["election_id"],
                "voter_hash": row["voter_hash"],
                "party": row["selection"],
                "vote_signature": row["vote_signature"],
                "timestamp": row["tx_timestamp"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def get_pending_encrypted_ballots():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT election_id, encrypted_ballot, receipt_hash, token_fingerprint, token_signature, homomorphic_ballot, tx_timestamp
            FROM ballots
            WHERE status = 'pending' AND encrypted_ballot IS NOT NULL
            ORDER BY id
            """
        ).fetchall()
        return [
            {
                "election_id": row["election_id"],
                "encrypted_ballot": row["encrypted_ballot"],
                "receipt_hash": row["receipt_hash"],
                "token_fingerprint": row["token_fingerprint"],
                "token_signature": row["token_signature"],
                "homomorphic_ballot": row["homomorphic_ballot"],
                "timestamp": row["tx_timestamp"],
            }
            for row in rows
        ]
    finally:
        connection.close()


def mark_ballots_confirmed(transactions, block_index, block_hash):
    connection = get_connection()
    try:
        for tx in transactions:
            actor_key = tx.get("voter_hash") or tx.get("token_fingerprint")
            receipt_hash = tx.get("receipt_hash")
            if actor_key:
                connection.execute(
                    """
                    UPDATE ballots
                    SET status = 'confirmed', block_index = ?, block_hash = ?
                    WHERE election_id = ? AND voter_hash = ? AND status = 'pending'
                    """,
                    (
                        block_index,
                        block_hash,
                        tx["election_id"],
                        actor_key,
                    )
                )
            elif receipt_hash:
                connection.execute(
                    """
                    UPDATE ballots
                    SET status = 'confirmed', block_index = ?, block_hash = ?
                    WHERE election_id = ? AND receipt_hash = ? AND status = 'pending'
                    """,
                    (
                        block_index,
                        block_hash,
                        tx["election_id"],
                        receipt_hash,
                    )
                )
        connection.commit()
    finally:
        connection.close()


def persist_block(block):
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT OR REPLACE INTO blocks (
                block_index, previous_hash, block_hash, nonce,
                timestamp, transactions_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                block.index,
                block.previous_hash,
                block.hash,
                block.nonce,
                block.timestamp,
                json.dumps(block.transactions, sort_keys=True),
                time.time()
            )
        )
        connection.commit()
    finally:
        connection.close()


def replace_blocks(blocks):
    connection = get_connection()
    try:
        connection.execute("DELETE FROM blocks")
        for block in blocks:
            connection.execute(
                """
                INSERT INTO blocks (
                    block_index, previous_hash, block_hash, nonce,
                    timestamp, transactions_json, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    block["index"],
                    block["previous_hash"],
                    block["hash"],
                    block["nonce"],
                    block["timestamp"],
                    json.dumps(block["transactions"], sort_keys=True),
                    time.time()
                )
            )
        connection.commit()
    finally:
        connection.close()


def _canonical_homomorphic_ballot(value):
    if not value:
        return None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return value
    return json.dumps(value, sort_keys=True)


def _confirmed_ballot_rows_from_chain(blocks):
    rows = []
    for block in blocks:
        for tx in block["transactions"]:
            selection = tx.get("party") or tx.get("selection")
            encrypted_ballot = tx.get("encrypted_ballot")
            if not selection and encrypted_ballot:
                payload = crypto_utils.decrypt_ballot_payload(encrypted_ballot)
                selection = payload.get("selection")

            rows.append(
                {
                    "election_id": tx["election_id"],
                    "voter_hash": tx.get("voter_hash") or tx.get("token_fingerprint", ""),
                    "selection": selection or "Encrypted ballot",
                    "vote_signature": tx.get("vote_signature") or tx.get("receipt_hash", ""),
                    "tx_timestamp": tx["timestamp"],
                    "status": "confirmed",
                    "block_index": block["index"],
                    "block_hash": block["hash"],
                    "receipt_hash": tx.get("receipt_hash"),
                    "encrypted_ballot": encrypted_ballot,
                    "token_fingerprint": tx.get("token_fingerprint"),
                    "token_signature": tx.get("token_signature"),
                    "homomorphic_ballot": _canonical_homomorphic_ballot(tx.get("homomorphic_ballot")),
                }
            )
    return rows


def get_confirmed_ballot_view():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                election_id,
                voter_hash,
                selection,
                vote_signature,
                tx_timestamp,
                status,
                block_index,
                block_hash,
                receipt_hash,
                encrypted_ballot,
                token_fingerprint,
                token_signature,
                homomorphic_ballot
            FROM ballots
            WHERE status = 'confirmed'
            ORDER BY block_index, tx_timestamp, vote_signature
            """
        ).fetchall()
        return [
            {
                "election_id": row["election_id"],
                "voter_hash": row["voter_hash"],
                "selection": row["selection"],
                "vote_signature": row["vote_signature"],
                "tx_timestamp": row["tx_timestamp"],
                "status": row["status"],
                "block_index": row["block_index"],
                "block_hash": row["block_hash"],
                "receipt_hash": row["receipt_hash"],
                "encrypted_ballot": row["encrypted_ballot"],
                "token_fingerprint": row["token_fingerprint"],
                "token_signature": row["token_signature"],
                "homomorphic_ballot": _canonical_homomorphic_ballot(row["homomorphic_ballot"]),
            }
            for row in rows
        ]
    finally:
        connection.close()


def confirmed_ballot_view_matches_chain(blocks):
    derived = sorted(
        _confirmed_ballot_rows_from_chain(blocks),
        key=lambda row: (row["block_index"], row["tx_timestamp"], row["vote_signature"]),
    )
    stored = get_confirmed_ballot_view()
    return stored == derived


def rebuild_confirmed_ballots_from_chain(blocks):
    confirmed_rows = _confirmed_ballot_rows_from_chain(blocks)
    connection = get_connection()
    try:
        connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
        for row in confirmed_rows:
            connection.execute(
                """
                INSERT INTO ballots (
                    election_id, voter_hash, selection, vote_signature, tx_timestamp,
                    status, block_index, block_hash, created_at,
                    receipt_hash, encrypted_ballot, token_fingerprint, token_signature, homomorphic_ballot
                )
                VALUES (?, ?, ?, ?, ?, 'confirmed', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["election_id"],
                    row["voter_hash"],
                    row["selection"],
                    row["vote_signature"],
                    row["tx_timestamp"],
                    row["block_index"],
                    row["block_hash"],
                    time.time(),
                    row["receipt_hash"],
                    row["encrypted_ballot"],
                    row["token_fingerprint"],
                    row["token_signature"],
                    row["homomorphic_ballot"],
                )
            )
        connection.commit()
    finally:
        connection.close()


def rebuild_ballots_from_chain(blocks):
    connection = get_connection()
    try:
        connection.execute("DELETE FROM ballots")
        for row in _confirmed_ballot_rows_from_chain(blocks):
            connection.execute(
                """
                INSERT INTO ballots (
                    election_id, voter_hash, selection, vote_signature, tx_timestamp,
                    status, block_index, block_hash, created_at,
                    receipt_hash, encrypted_ballot, token_fingerprint, token_signature, homomorphic_ballot
                )
                VALUES (?, ?, ?, ?, ?, 'confirmed', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row["election_id"],
                    row["voter_hash"],
                    row["selection"],
                    row["vote_signature"],
                    row["tx_timestamp"],
                    row["block_index"],
                    row["block_hash"],
                    time.time(),
                    row["receipt_hash"],
                    row["encrypted_ballot"],
                    row["token_fingerprint"],
                    row["token_signature"],
                    row["homomorphic_ballot"],
                )
            )
        connection.commit()
    finally:
        connection.close()


def load_blocks():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT block_index, previous_hash, block_hash, nonce, timestamp, transactions_json
            FROM blocks
            ORDER BY block_index
            """
        ).fetchall()
        return [
            {
                "index": row["block_index"],
                "previous_hash": row["previous_hash"],
                "hash": row["block_hash"],
                "nonce": row["nonce"],
                "timestamp": row["timestamp"],
                "transactions": json.loads(row["transactions_json"])
            }
            for row in rows
        ]
    finally:
        connection.close()


def record_audit_event(event_type, actor_type, actor_id=None, election_id=None, details=None):
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT INTO audit_events (
                event_type, actor_type, actor_id, election_id, details_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                actor_type,
                actor_id,
                election_id,
                json.dumps(details or {}, sort_keys=True),
                time.time()
            )
        )
        connection.commit()
    finally:
        connection.close()


def list_audit_events(limit=100, event_type=None, actor_type=None):
    connection = get_connection()
    try:
        if event_type and actor_type:
            rows = connection.execute(
                """
                SELECT event_type, actor_type, actor_id, election_id, details_json, created_at
                FROM audit_events
                WHERE event_type = ? AND actor_type = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (event_type, actor_type, limit)
            ).fetchall()
        elif event_type:
            rows = connection.execute(
                """
                SELECT event_type, actor_type, actor_id, election_id, details_json, created_at
                FROM audit_events
                WHERE event_type = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (event_type, limit)
            ).fetchall()
        elif actor_type:
            rows = connection.execute(
                """
                SELECT event_type, actor_type, actor_id, election_id, details_json, created_at
                FROM audit_events
                WHERE actor_type = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (actor_type, limit)
            ).fetchall()
        else:
            rows = connection.execute(
                """
                SELECT event_type, actor_type, actor_id, election_id, details_json, created_at
                FROM audit_events
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,)
            ).fetchall()
        return [
            {
                "event_type": row["event_type"],
                "actor_type": row["actor_type"],
                "actor_id": row["actor_id"],
                "election_id": row["election_id"],
                "details": json.loads(row["details_json"]),
                "created_at": row["created_at"]
            }
            for row in rows
        ]
    finally:
        connection.close()


def get_vote_counts(election_id):
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT selection, COUNT(*) AS total
            FROM ballots
            WHERE election_id = ? AND status = 'confirmed'
            GROUP BY selection
            ORDER BY selection
            """,
            (election_id,)
        ).fetchall()
        return {row["selection"]: row["total"] for row in rows}
    finally:
        connection.close()


def get_ballot_by_signature(vote_signature):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT
                b.election_id,
                e.name AS election_name,
                b.voter_hash,
                b.selection,
                b.vote_signature,
                b.tx_timestamp,
                b.status,
                b.block_index,
                b.block_hash
            FROM ballots b
            JOIN elections e ON e.id = b.election_id
            WHERE b.vote_signature = ?
            LIMIT 1
            """,
            (vote_signature,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def get_ballot_by_receipt(receipt_hash):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT
                b.election_id,
                e.name AS election_name,
                b.voter_hash,
                b.selection,
                b.receipt_hash,
                b.tx_timestamp,
                b.status,
                b.block_index,
                b.block_hash,
                b.encrypted_ballot,
                b.token_fingerprint
            FROM ballots b
            JOIN elections e ON e.id = b.election_id
            WHERE b.receipt_hash = ?
            LIMIT 1
            """,
            (receipt_hash,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def list_bulletin_board():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT election_id, receipt_hash, token_fingerprint, encrypted_ballot, homomorphic_ballot, status, block_index, tx_timestamp
            FROM ballots
            WHERE encrypted_ballot IS NOT NULL
            ORDER BY id
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_confirmed_homomorphic_ballots(election_id):
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT homomorphic_ballot
            FROM ballots
            WHERE election_id = ? AND status = 'confirmed' AND homomorphic_ballot IS NOT NULL
            ORDER BY id
            """,
            (election_id,)
        ).fetchall()
        return [row["homomorphic_ballot"] for row in rows]
    finally:
        connection.close()


def initialize_tally_authorities(authority_shares):
    connection = get_connection()
    try:
        existing = connection.execute("SELECT COUNT(*) FROM tally_authorities").fetchone()[0]
        if existing:
            return

        now = time.time()
        connection.executemany(
            """
            INSERT INTO tally_authorities (
                authority_name, authority_index, share_value_hex, public_commitment_hex, is_active, created_at
            )
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            [
                (
                    "Authority {}".format(share["authority_index"]),
                    share["authority_index"],
                    format(share["share_value"], "x"),
                    format(share["public_commitment"], "x"),
                    now,
                )
                for share in authority_shares
            ],
        )
        connection.commit()
    finally:
        connection.close()


def list_tally_authorities():
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT authority_name, authority_index, share_value_hex, public_commitment_hex, is_active
            FROM tally_authorities
            ORDER BY authority_index
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_tally_authority(authority_name):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT authority_name, authority_index, share_value_hex, public_commitment_hex, is_active
            FROM tally_authorities
            WHERE authority_name = ?
            LIMIT 1
            """,
            (authority_name,),
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def clear_partial_decryptions(election_id, tally_fingerprint):
    connection = get_connection()
    try:
        connection.execute(
            """
            DELETE FROM tally_partial_decryptions
            WHERE election_id = ? AND tally_fingerprint = ?
            """,
            (election_id, tally_fingerprint),
        )
        connection.commit()
    finally:
        connection.close()


def record_partial_decryption(
    election_id,
    tally_fingerprint,
    option_index,
    authority_name,
    partial_value_hex,
    signature_hex="",
):
    connection = get_connection()
    try:
        connection.execute(
            """
            INSERT OR IGNORE INTO tally_partial_decryptions (
                election_id, tally_fingerprint, option_index, authority_name, partial_value_hex, signature_hex, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                election_id,
                tally_fingerprint,
                option_index,
                authority_name,
                partial_value_hex,
                signature_hex,
                time.time(),
            ),
        )
        connection.commit()
    finally:
        connection.close()


def list_partial_decryptions(election_id, tally_fingerprint):
    connection = get_connection()
    try:
        rows = connection.execute(
            """
            SELECT option_index, authority_name, partial_value_hex, signature_hex, created_at
            FROM tally_partial_decryptions
            WHERE election_id = ? AND tally_fingerprint = ?
            ORDER BY option_index, authority_name
            """,
            (election_id, tally_fingerprint),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_rate_limit_status(action, actor_key):
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT attempt_count, window_started, blocked_until, updated_at
            FROM rate_limits
            WHERE action = ? AND actor_key = ?
            """,
            (action, actor_key)
        ).fetchone()
        return dict(row) if row else None
    finally:
        connection.close()


def reset_rate_limit(action, actor_key):
    connection = get_connection()
    try:
        connection.execute(
            "DELETE FROM rate_limits WHERE action = ? AND actor_key = ?",
            (action, actor_key)
        )
        connection.commit()
    finally:
        connection.close()


def register_rate_limit_attempt(action, actor_key, max_attempts, window_seconds, block_seconds):
    now = time.time()
    connection = get_connection()
    try:
        row = connection.execute(
            """
            SELECT attempt_count, window_started, blocked_until
            FROM rate_limits
            WHERE action = ? AND actor_key = ?
            """,
            (action, actor_key)
        ).fetchone()

        if not row:
            connection.execute(
                """
                INSERT INTO rate_limits (
                    action, actor_key, attempt_count, window_started, blocked_until, updated_at
                )
                VALUES (?, ?, 1, ?, NULL, ?)
                """,
                (action, actor_key, now, now)
            )
            connection.commit()
            return {"allowed": True, "retry_after": 0, "attempt_count": 1}

        blocked_until = row["blocked_until"] or 0
        if blocked_until > now:
            return {
                "allowed": False,
                "retry_after": int(blocked_until - now),
                "attempt_count": row["attempt_count"]
            }

        attempt_count = row["attempt_count"]
        window_started = row["window_started"]
        if now - window_started > window_seconds:
            attempt_count = 0
            window_started = now

        attempt_count += 1
        new_blocked_until = None
        allowed = True
        retry_after = 0

        if attempt_count >= max_attempts:
            allowed = False
            new_blocked_until = now + block_seconds
            retry_after = block_seconds

        connection.execute(
            """
            INSERT OR REPLACE INTO rate_limits (
                action, actor_key, attempt_count, window_started, blocked_until, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (action, actor_key, attempt_count, window_started, new_blocked_until, now)
        )
        connection.commit()
        return {"allowed": allowed, "retry_after": retry_after, "attempt_count": attempt_count}
    finally:
        connection.close()
