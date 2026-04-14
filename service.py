from hashlib import sha256
import json
import time

from flask import Flask, jsonify, request
import requests

import crypto_utils
import storage
import tally_authorities
from logging_config import setup_logging


class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce

    def hash_payload(self):
        return {
            "index": self.index,
            "transactions": self.transactions,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
        }

    def compute_hash(self):
        payload = json.dumps(self.hash_payload(), sort_keys=True, separators=(",", ":"))
        return sha256(payload.encode("utf-8")).hexdigest()


class Blockchain:
    difficulty = 2

    def __init__(self):
        self.unconfirmed_transactions = self._load_pending_transactions()
        self.chain = []

    @staticmethod
    def _load_pending_transactions():
        encrypted = storage.get_pending_encrypted_ballots()
        if encrypted:
            return encrypted
        return storage.get_pending_ballots()

    def create_genesis_block(self):
        genesis_block = Block(0, [], 0, "0")
        genesis_block.hash = self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)
        storage.persist_block(genesis_block)

    @property
    def last_block(self):
        return self.chain[-1]

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash

        if previous_hash != block.previous_hash:
            return False

        if not self.is_valid_proof(block, proof):
            return False

        block.hash = proof
        self.chain.append(block)
        storage.persist_block(block)
        storage.mark_ballots_confirmed(block.transactions, block.index, proof)
        return True

    @staticmethod
    def proof_of_work(block):
        block.nonce = 0

        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()

        return computed_hash

    def add_new_transaction(self, transaction):
        self.refresh_unconfirmed_transactions()
        self.unconfirmed_transactions.append(transaction)

    def refresh_unconfirmed_transactions(self):
        self.unconfirmed_transactions = self._load_pending_transactions()

    @classmethod
    def is_valid_proof(cls, block, block_hash):
        return (block_hash.startswith('0' * cls.difficulty) and
                block_hash == block.compute_hash())

    @classmethod
    def check_chain_validity(cls, chain):
        """Validate the chain for both Block objects and serialized dicts."""
        previous_hash = "0"

        for block in chain:
            block_obj = cls._coerce_block(block)
            if block_obj is None or not hasattr(block_obj, "hash"):
                return False

            block_hash = block_obj.hash

            valid = cls.is_valid_proof(block_obj, block_hash) and \
                    previous_hash == block_obj.previous_hash

            if not valid:
                return False

            previous_hash = block_hash

        return True

    @staticmethod
    def _coerce_block(block):
        """Build a Block instance from an incoming dict when needed."""
        if isinstance(block, Block):
            return block

        if not isinstance(block, dict):
            return None

        required_fields = ["index", "transactions", "timestamp", "previous_hash", "nonce", "hash"]
        if any(field not in block for field in required_fields):
            return None

        block_obj = Block(
            block["index"],
            block["transactions"],
            block["timestamp"],
            block["previous_hash"],
            block["nonce"],
        )
        block_obj.hash = block["hash"]
        return block_obj

    def mine(self):
        if not self.unconfirmed_transactions:
            return False

        last_block = self.last_block

        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)

        proof = self.proof_of_work(new_block)
        self.add_block(new_block, proof)

        self.unconfirmed_transactions = []

        return True


app = Flask(__name__)
logger = setup_logging("service")
storage.initialize_storage()


def json_response(payload, status=200):
    response = jsonify(payload)
    response.status_code = status
    return response


def ensure_tally_authorities():
    return tally_authorities.ensure_authorities_initialized()


@app.route('/crypto/public_material', methods=['GET'])
def crypto_public_material():
    return json_response(crypto_utils.export_public_material())


@app.route('/issue_token', methods=['POST'])
def issue_token():
    tx_data = request.get_json(silent=True) or {}
    required_fields = ["voter_hash", "election_id", "blinded_token"]
    for field in required_fields:
        if not tx_data.get(field):
            return json_response({"error": "Invalid token request"}, 400)

    voter_hash = tx_data["voter_hash"]
    election_id = tx_data["election_id"]
    blinded_token = tx_data["blinded_token"]

    active_election = storage.get_active_election()
    if not active_election or active_election["id"] != election_id:
        return json_response({"error": "Election is not active"}, 400)

    if not storage.is_valid_voter_hash(voter_hash):
        return json_response({"error": "Invalid voter hash"}, 400)

    if voter_hash not in storage.get_registered_voter_hashes():
        return json_response({"error": "Voter not registered"}, 400)

    if storage.voter_has_token(election_id, voter_hash) or storage.ballot_exists(election_id, voter_hash):
        return json_response({"error": "Anonymous token already issued"}, 400)

    created = storage.issue_anonymous_token(election_id, voter_hash)
    if not created:
        return json_response({"error": "Anonymous token already issued"}, 400)

    blind_signature = crypto_utils.sign_blinded_token(blinded_token)
    storage.record_audit_event(
        "anonymous_token_issued",
        "voter",
        actor_id=voter_hash,
        election_id=election_id
    )
    return json_response({"blind_signature": blind_signature}, 201)


@app.route('/cast_ballot', methods=['POST'])
def cast_ballot():
    tx_data = request.get_json(silent=True) or {}
    required_fields = [
        "election_id",
        "token_message",
        "token_signature",
        "encrypted_ballot",
        "receipt_hash",
        "homomorphic_ballot",
    ]
    for field in required_fields:
        if not tx_data.get(field):
            return json_response({"error": "Invalid encrypted ballot"}, 400)

    election_id = tx_data["election_id"]
    token_message = tx_data["token_message"]
    token_signature = tx_data["token_signature"]
    encrypted_ballot = tx_data["encrypted_ballot"]
    receipt_hash = tx_data["receipt_hash"]
    homomorphic_ballot = tx_data["homomorphic_ballot"]

    active_election = storage.get_active_election()
    if not active_election or active_election["id"] != election_id:
        return json_response({"error": "Election is not active"}, 400)

    if not storage.is_valid_vote_signature(receipt_hash):
        return json_response({"error": "Invalid receipt hash"}, 400)

    if not crypto_utils.verify_token_signature(token_message, token_signature):
        return json_response({"error": "Invalid anonymous token signature"}, 400)

    computed_receipt = crypto_utils.ballot_receipt_hash(encrypted_ballot)
    if computed_receipt != receipt_hash:
        return json_response({"error": "Receipt hash mismatch"}, 400)

    token_fingerprint = crypto_utils.token_fingerprint(token_message)
    if storage.is_token_spent(token_fingerprint):
        return json_response({"error": "Anonymous token already spent"}, 400)

    try:
        ballot_payload = crypto_utils.decrypt_ballot_payload(encrypted_ballot)
    except Exception:
        return json_response({"error": "Encrypted ballot could not be decrypted"}, 400)

    if ballot_payload.get("election_id") != election_id:
        return json_response({"error": "Ballot election mismatch"}, 400)

    selection = ballot_payload.get("selection")
    if not storage.is_valid_election_option(election_id, selection):
        return json_response({"error": "Ballot choice is invalid"}, 400)

    if not isinstance(homomorphic_ballot, dict):
        return json_response({"error": "Homomorphic ballot is invalid"}, 400)

    if homomorphic_ballot.get("options") != active_election["options"]:
        return json_response({"error": "Homomorphic ballot options mismatch"}, 400)

    ciphertexts = homomorphic_ballot.get("ciphertexts")
    if not isinstance(ciphertexts, list) or len(ciphertexts) != len(active_election["options"]):
        return json_response({"error": "Homomorphic ballot structure is invalid"}, 400)

    validity_proofs = homomorphic_ballot.get("validity_proofs")
    if not isinstance(validity_proofs, list) or len(validity_proofs) != len(ciphertexts):
        return json_response({"error": "Homomorphic ballot proofs are invalid"}, 400)

    if not crypto_utils.verify_ballot_sum_proof(ciphertexts, homomorphic_ballot.get("sum_proof", {})):
        return json_response({"error": "Homomorphic ballot sum proof mismatch"}, 400)

    for ciphertext, proof in zip(ciphertexts, validity_proofs):
        if not crypto_utils.verify_ciphertext_bit_proof(ciphertext, proof):
            return json_response({"error": "Homomorphic ballot proof mismatch"}, 400)

    try:
        decrypted_vector = [
            crypto_utils.decrypt_homomorphic_count(ciphertext, 1)
            for ciphertext in ciphertexts
        ]
    except Exception:
        return json_response({"error": "Homomorphic ballot proof mismatch"}, 400)

    if sum(decrypted_vector) != 1:
        return json_response({"error": "Homomorphic ballot must encode exactly one choice"}, 400)

    selected_index = active_election["options"].index(selection)
    if decrypted_vector[selected_index] != 1:
        return json_response({"error": "Homomorphic ballot proof mismatch"}, 400)

    spent = storage.spend_token(election_id, token_fingerprint, receipt_hash)
    if not spent:
        return json_response({"error": "Anonymous token already spent"}, 400)

    tx_timestamp = time.time()
    created = storage.create_encrypted_ballot(
        election_id=election_id,
        token_fingerprint=token_fingerprint,
        encrypted_ballot=encrypted_ballot,
        receipt_hash=receipt_hash,
        token_signature=token_signature,
        tx_timestamp=tx_timestamp,
        selection=selection,
        homomorphic_ballot=json.dumps(homomorphic_ballot, sort_keys=True),
    )
    if not created:
        return json_response({"error": "Encrypted ballot could not be stored"}, 400)

    tx = {
        "election_id": election_id,
        "token_fingerprint": token_fingerprint,
        "receipt_hash": receipt_hash,
        "encrypted_ballot": encrypted_ballot,
        "token_signature": token_signature,
        "homomorphic_ballot": homomorphic_ballot,
        "timestamp": tx_timestamp,
    }
    blockchain.add_new_transaction(tx)
    storage.record_audit_event(
        "encrypted_ballot_cast",
        "token",
        actor_id=token_fingerprint,
        election_id=election_id,
        details={"receipt_hash": receipt_hash}
    )
    return json_response({
        "message": "Encrypted ballot accepted",
        "receipt_hash": receipt_hash,
        "token_fingerprint": token_fingerprint,
        "homomorphic_ballot_hash": crypto_utils.homomorphic_ballot_hash(homomorphic_ballot),
    }, 201)

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json(silent=True) or {}
    required_fields = ["voter_hash", "party", "election_id"]

    for field in required_fields:
        if not tx_data.get(field):
            return json_response({"error": "Invalid transaction data"}, 400)

    voter_hash = tx_data["voter_hash"]
    party = tx_data["party"]
    election_id = tx_data["election_id"]

    if not isinstance(election_id, int) or election_id <= 0:
        return json_response({"error": "Invalid election identifier"}, 400)

    if not storage.is_valid_voter_hash(voter_hash):
        return json_response({"error": "Invalid voter hash"}, 400)

    if not isinstance(party, str) or len(party.strip()) == 0 or len(party) > 100:
        return json_response({"error": "Invalid election option"}, 400)
    active_election = storage.get_active_election()

    if not active_election or active_election["id"] != election_id:
        return json_response({"error": "Election is not active"}, 400)

    if not storage.is_valid_election_option(election_id, party):
        return json_response({"error": "Invalid election option"}, 400)

    # Authentication: only allow votes from registered voters (without knowing real ID).
    if voter_hash not in storage.get_registered_voter_hashes():
        return json_response({"error": "Voter not registered"}, 400)

    if storage.ballot_exists(election_id, voter_hash):
        storage.record_audit_event(
            "double_vote_blocked",
            "voter",
            actor_id=voter_hash,
            election_id=election_id,
            details={"party": party}
        )
        return json_response({"error": "Voter has already voted"}, 400)

    # Add a second hash that includes the previous block's hash to mimic the linkage
    # described in the paper (prevents straightforward correlation between votes).
    previous_hash = blockchain.last_block.hash if blockchain.chain else "0"
    vote_signature = sha256((voter_hash + previous_hash).encode()).hexdigest()

    tx = {
        "election_id": election_id,
        "voter_hash": voter_hash,
        "vote_signature": vote_signature,
        "party": party,
        "timestamp": time.time()
    }

    created = storage.create_ballot(
        election_id=election_id,
        voter_hash=voter_hash,
        selection=party,
        vote_signature=vote_signature,
        tx_timestamp=tx["timestamp"],
    )
    if not created:
        return json_response({"error": "Voter has already voted"}, 400)

    blockchain.add_new_transaction(tx)
    storage.record_audit_event(
        "vote_submitted",
        "voter",
        actor_id=voter_hash,
        election_id=election_id,
        details={"party": party}
    )
    logger.info("Accepted vote for election_id=%s voter_hash=%s", election_id, voter_hash)

    return json_response({
        "message": "Success",
        "vote_signature": vote_signature,
        "voter_hash": voter_hash
    }, 201)


@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = []
    for block in blockchain.chain:
        chain_data.append(block.__dict__)
    return json_response({"length": len(chain_data),
                          "chain": chain_data,
                          "peers": list(peers)})


def get_vote_counts_from_chain(election_id):
    counts = {}

    for block in blockchain.chain:
        for transaction in block.transactions:
            if transaction.get("election_id") != election_id:
                continue

            selection = transaction.get("party")
            if not selection and transaction.get("encrypted_ballot"):
                try:
                    payload = crypto_utils.decrypt_ballot_payload(transaction["encrypted_ballot"])
                except Exception:
                    logger.warning(
                        "Skipping undecryptable ballot while tallying chain results for election_id=%s",
                        election_id,
                    )
                    continue
                selection = payload.get("selection")

            if not selection or not storage.is_valid_election_option(election_id, selection):
                continue

            counts[selection] = counts.get(selection, 0) + 1

    return counts


def get_vote_counts_from_confirmed_view(election_id):
    return storage.get_vote_counts(election_id)


def get_bulletin_board_view():
    items = []

    for block in blockchain.chain:
        if block.index == 0:
            continue

        for transaction in block.transactions:
            if not transaction.get("encrypted_ballot"):
                continue

            item = {
                "election_id": transaction["election_id"],
                "receipt_hash": transaction.get("receipt_hash"),
                "token_fingerprint": transaction.get("token_fingerprint"),
                "encrypted_ballot": transaction.get("encrypted_ballot"),
                "homomorphic_ballot": transaction.get("homomorphic_ballot"),
                "status": "confirmed",
                "block_index": block.index,
                "tx_timestamp": transaction.get("timestamp"),
            }
            items.append(item)

    for transaction in storage.get_pending_encrypted_ballots():
        items.append(
            {
                "election_id": transaction["election_id"],
                "receipt_hash": transaction.get("receipt_hash"),
                "token_fingerprint": transaction.get("token_fingerprint"),
                "encrypted_ballot": transaction.get("encrypted_ballot"),
                "homomorphic_ballot": transaction.get("homomorphic_ballot"),
                "status": "pending",
                "block_index": None,
                "tx_timestamp": transaction.get("timestamp"),
            }
        )

    return items


def get_confirmed_homomorphic_ballots_from_chain(election_id):
    ballots = []

    for block in blockchain.chain:
        if block.index == 0:
            continue

        for transaction in block.transactions:
            if transaction.get("election_id") != election_id:
                continue

            homomorphic_ballot = transaction.get("homomorphic_ballot")
            if not homomorphic_ballot:
                continue

            if isinstance(homomorphic_ballot, dict):
                ballots.append(json.dumps(homomorphic_ballot, sort_keys=True))
            else:
                ballots.append(homomorphic_ballot)

    return ballots


def _serialize_chain_dump():
    chain_dump = []
    for block in blockchain.chain:
        chain_dump.append(
            {
                "index": block.index,
                "previous_hash": block.previous_hash,
                "hash": block.hash,
                "nonce": block.nonce,
                "timestamp": block.timestamp,
                "transactions": block.transactions,
            }
        )
    return chain_dump


def ensure_confirmed_ballot_view_consistency():
    chain_dump = _serialize_chain_dump()
    try:
        if storage.confirmed_ballot_view_matches_chain(chain_dump):
            return {"ok": True, "repaired": False}

        logger.warning("Confirmed ballot view drift detected; rebuilding from blockchain")
        storage.rebuild_confirmed_ballots_from_chain(chain_dump)

        if storage.confirmed_ballot_view_matches_chain(chain_dump):
            return {"ok": True, "repaired": True}
    except Exception as exc:
        logger.warning("Confirmed ballot view consistency check failed: %s", exc)
        return {"ok": False, "repaired": False, "error": str(exc)}

    return {
        "ok": False,
        "repaired": True,
        "error": "Confirmed ballot view does not match blockchain after rebuild",
    }


@app.route('/results', methods=['GET'])
def get_results():
    """Return vote counts derived from confirmed blockchain state."""
    active_election = storage.get_active_election()
    if not active_election:
        return json_response({})
    consistency = ensure_confirmed_ballot_view_consistency()
    if not consistency["ok"]:
        return json_response({"error": "Ballot view is inconsistent with blockchain"}, 409)
    counts = get_vote_counts_from_chain(active_election["id"])
    return json_response(counts)


@app.route('/homomorphic_results', methods=['GET'])
def get_homomorphic_results():
    active_election = storage.get_active_election()
    if not active_election:
        return json_response({"totals": {}, "ballot_count": 0, "aggregated_ciphertexts": []})
    consistency = ensure_confirmed_ballot_view_consistency()
    if not consistency["ok"]:
        return json_response({"error": "Ballot view is inconsistent with blockchain"}, 409)

    authorities = ensure_tally_authorities()
    serialized_ballots = get_confirmed_homomorphic_ballots_from_chain(active_election["id"])
    base_tally = crypto_utils.tally_homomorphic_ballots(serialized_ballots, len(serialized_ballots))
    tally_fingerprint = crypto_utils.homomorphic_ballot_hash(
        {
            "options": base_tally["options"],
            "aggregated_ciphertexts": base_tally["aggregated_ciphertexts"],
            "ballot_count": len(serialized_ballots),
        }
    ) if serialized_ballots else ""

    tally_authorities.materialize_threshold_contributions(
        active_election["id"],
        tally_fingerprint,
        base_tally["aggregated_ciphertexts"],
        app.config.get("TALLY_THRESHOLD", 2),
    )
    threshold_session = tally_authorities.collect_threshold_session(
        active_election["id"],
        tally_fingerprint,
    )

    threshold_ready = (
        bool(base_tally["aggregated_ciphertexts"]) and
        all(
            len(threshold_session["partial_by_option"].get(index, [])) >= app.config.get("TALLY_THRESHOLD", 2)
            for index in range(len(base_tally["aggregated_ciphertexts"]))
        )
    )

    if threshold_ready:
        reconstructed_secret = tally_authorities.reconstruct_secret_from_session(
            threshold_session,
            app.config.get("TALLY_THRESHOLD", 2),
        )
        tally = crypto_utils.tally_homomorphic_ballots_with_secret(
            serialized_ballots,
            len(serialized_ballots),
            reconstructed_secret,
        )
    else:
        tally = {
            "options": base_tally["options"],
            "totals": {},
            "aggregated_ciphertexts": base_tally["aggregated_ciphertexts"],
        }

    return json_response({
        "election_id": active_election["id"],
        "election_name": active_election["name"],
        "ballot_count": len(serialized_ballots),
        "options": tally["options"],
        "totals": tally["totals"],
        "aggregated_ciphertexts": tally["aggregated_ciphertexts"],
        "public_material": crypto_utils.export_public_material()["homomorphic_tally"],
        "threshold": {
            "ready": threshold_ready,
            "mode": "shamir_reconstruction_{}_of_{}".format(
                app.config.get("TALLY_THRESHOLD", 2),
                len(authorities),
            ),
            "threshold": app.config.get("TALLY_THRESHOLD", 2),
            "authority_count": len(authorities),
            "tally_fingerprint": tally_fingerprint,
            "authorities": threshold_session["authority_status"],
            "proof_artifacts": threshold_session["proof_artifacts"],
        },
    })


@app.route('/verify_receipt/<receipt_hash>', methods=['GET'])
def verify_receipt(receipt_hash):
    if not storage.is_valid_vote_signature(receipt_hash):
        return json_response({"error": "Invalid receipt hash"}, 400)
    consistency = ensure_confirmed_ballot_view_consistency()
    if not consistency["ok"]:
        return json_response({"error": "Ballot view is inconsistent with blockchain"}, 409)

    ballot = storage.get_ballot_by_receipt(receipt_hash)
    if not ballot:
        return json_response({"found": False, "receipt_hash": receipt_hash}, 404)

    return json_response({
        "found": True,
        "receipt_hash": receipt_hash,
        "status": ballot["status"],
        "block_index": ballot["block_index"],
        "token_fingerprint": ballot["token_fingerprint"],
        "election_name": ballot["election_name"],
    })


@app.route('/bulletin_board', methods=['GET'])
def bulletin_board():
    consistency = ensure_confirmed_ballot_view_consistency()
    if not consistency["ok"]:
        return json_response({"error": "Ballot view is inconsistent with blockchain"}, 409)

    return json_response({
        "items": get_bulletin_board_view(),
        "valid_chain": blockchain.check_chain_validity(blockchain.chain),
        "length": len(blockchain.chain),
        "ballot_view_consistent": True,
    })


@app.route('/integrity_status', methods=['GET'])
def integrity_status():
    chain_valid = blockchain.check_chain_validity(blockchain.chain)
    consistency = ensure_confirmed_ballot_view_consistency() if chain_valid else {
        "ok": False,
        "repaired": False,
        "error": "Blockchain is invalid",
    }

    return json_response({
        "chain_valid": chain_valid,
        "chain_length": len(blockchain.chain),
        "ballot_view_consistent": consistency["ok"],
        "ballot_view_repaired": consistency.get("repaired", False),
        "pending_transaction_count": len(blockchain.unconfirmed_transactions),
        "confirmed_encrypted_ballot_count": len(
            [item for item in get_bulletin_board_view() if item["status"] == "confirmed"]
        ) if chain_valid else 0,
        "error": consistency.get("error"),
    }, 200 if chain_valid and consistency["ok"] else 409)


@app.route('/result_consistency', methods=['GET'])
def result_consistency():
    active_election = storage.get_active_election()
    if not active_election:
        return json_response(
            {
                "election_id": None,
                "election_name": None,
                "chain_counts": {},
                "derived_view_counts": {},
                "counts_match": True,
            }
        )

    chain_counts = get_vote_counts_from_chain(active_election["id"])
    derived_view_counts = get_vote_counts_from_confirmed_view(active_election["id"])
    return json_response(
        {
            "election_id": active_election["id"],
            "election_name": active_election["name"],
            "chain_counts": chain_counts,
            "derived_view_counts": derived_view_counts,
            "counts_match": chain_counts == derived_view_counts,
        }
    )


@app.route('/rebuild_state_from_chain', methods=['POST'])
def rebuild_state_from_chain():
    chain_valid = blockchain.check_chain_validity(blockchain.chain)
    if not chain_valid:
        return json_response({"error": "Blockchain is invalid"}, 409)

    chain_dump = _serialize_chain_dump()
    try:
        storage.rebuild_confirmed_ballots_from_chain(chain_dump)
        consistency = ensure_confirmed_ballot_view_consistency()
        if not consistency["ok"]:
            return json_response(
                {"error": consistency.get("error", "Rebuild failed")},
                409,
            )
    except Exception as exc:
        return json_response({"error": str(exc)}, 500)

    confirmed_count = len(storage.get_confirmed_ballot_view())
    storage.record_audit_event(
        "confirmed_ballot_view_rebuilt",
        "node",
        details={"confirmed_ballot_count": confirmed_count}
    )
    return json_response({
        "message": "Confirmed ballot view rebuilt from blockchain",
        "confirmed_ballot_count": confirmed_count,
    })


@app.route('/validate', methods=['GET'])
def validate_chain():
    """Validate the blockchain integrity (hash chain + proof-of-work)."""
    try:
        is_valid = blockchain.check_chain_validity(blockchain.chain)
    except Exception as e:
        return json_response({
            "valid": False,
            "error": str(e),
            "length": len(blockchain.chain),
            "difficulty": blockchain.difficulty,
        }, 500)

    return json_response({
        "valid": is_valid,
        "length": len(blockchain.chain),
        "difficulty": blockchain.difficulty,
    })


@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    blockchain.refresh_unconfirmed_transactions()
    result = blockchain.mine()
    if not result:
        return json_response({"message": "No transactions to mine"}, 200)
    else:
        chain_length = len(blockchain.chain)
        consensus()
        if chain_length == len(blockchain.chain):
            announce_new_block(blockchain.last_block)
        storage.record_audit_event(
            "block_mined",
            "node",
            details={"index": blockchain.last_block.index}
        )
        return json_response({
            "message": "Block #{} is mined.".format(blockchain.last_block.index),
            "index": blockchain.last_block.index
        })


@app.route('/register_node', methods=['POST'])
def register_new_peers():
    node_address = (request.get_json(silent=True) or {}).get("node_address")
    if not node_address:
        return json_response({"error": "Invalid data"}, 400)

    peers.add(node_address)
    storage.record_audit_event("peer_added", "node", actor_id=node_address)

    return get_chain()


@app.route('/register_with', methods=['POST'])
def register_with_existing_node():
    node_address = (request.get_json(silent=True) or {}).get("node_address")
    if not node_address:
        return json_response({"error": "Invalid data"}, 400)

    data = {"node_address": request.host_url}
    headers = {'Content-Type': "application/json"}

    try:
        response = requests.post(node_address + "/register_node",
                                 data=json.dumps(data), headers=headers, timeout=5)
    except requests.RequestException as exc:
        return json_response({"error": str(exc)}, 502)

    if response.status_code == 200:
        global blockchain
        global peers
        chain_dump = response.json()['chain']
        blockchain = create_chain_from_dump(chain_dump)
        peers.update(response.json()['peers'])
        storage.record_audit_event(
            "node_registered",
            "node",
            actor_id=node_address,
            details={"peer_count": len(peers)}
        )
        return json_response({"message": "Registration successful"}, 200)
    else:
        try:
            payload = response.json()
        except ValueError:
            payload = {"error": response.text}
        return json_response(payload, response.status_code)


def create_chain_from_dump(chain_dump, persist=True):
    generated_blockchain = Blockchain()
    generated_blockchain.chain = []
    for block_data in chain_dump:
        block = Blockchain._coerce_block(block_data)
        if block is None:
            raise Exception("The chain dump is malformed")

        if block.index == 0:
            genesis_hash = block.hash
            is_valid_genesis = (
                block.previous_hash == "0" and
                Blockchain.is_valid_proof(block, genesis_hash)
            )

            if not is_valid_genesis:
                raise Exception("The genesis block is invalid")
            generated_blockchain.chain.append(block)
            continue

        proof = block.hash
        added = generated_blockchain.add_block(block, proof)
        if not added:
            raise Exception("The chain dump is tampered")

    if not generated_blockchain.chain:
        raise Exception("The chain dump is empty")
    if persist:
        storage.replace_blocks(chain_dump)
        storage.rebuild_ballots_from_chain(chain_dump)
    return generated_blockchain


def load_blockchain():
    chain_dump = storage.load_blocks()
    if chain_dump:
        try:
            return create_chain_from_dump(chain_dump, persist=False)
        except Exception as exc:
            logger.warning("Stored chain could not be restored: %s", exc)
            storage.replace_blocks([])
            storage.rebuild_ballots_from_chain([])

    generated = Blockchain()
    generated.create_genesis_block()
    return generated


blockchain = load_blockchain()

peers = set()


@app.route('/add_block', methods=['POST'])
def verify_and_add_block():
    block_data = request.get_json(silent=True) or {}
    block = Blockchain._coerce_block(block_data)
    if block is None:
        return json_response({"error": "Invalid block data"}, 400)

    proof = block_data['hash']
    added = blockchain.add_block(block, proof)

    if not added:
        return json_response({"error": "The block was discarded by the node"}, 400)

    storage.record_audit_event(
        "block_received",
        "node",
        details={"index": block.index, "hash": proof}
    )
    return json_response({"message": "Block added to the chain"}, 201)


@app.route('/pending_tx')
def get_pending_tx():
    return json_response(blockchain.unconfirmed_transactions)


def consensus():
    global blockchain

    longest_chain = None
    current_len = len(blockchain.chain)

    for node in peers:
        try:
            response = requests.get('{}chain'.format(node), timeout=5)
            if response.status_code != 200:
                continue

            response_data = response.json()
            length = response_data['length']
            chain = response_data['chain']
            if length > current_len and Blockchain.check_chain_validity(chain):
                current_len = length
                longest_chain = chain
        except (requests.RequestException, ValueError, KeyError, TypeError):
            continue

    if longest_chain:
        blockchain = create_chain_from_dump(longest_chain)
        logger.info("Consensus replaced local chain with length=%s", len(blockchain.chain))
        return True

    return False


def announce_new_block(block):
    for peer in peers:
        url = "{}add_block".format(peer)
        headers = {'Content-Type': "application/json"}
        try:
            requests.post(url,
                          data=json.dumps(block.__dict__, sort_keys=True),
                          headers=headers,
                          timeout=5)
        except requests.RequestException:
            continue


@app.errorhandler(Exception)
def handle_exception(e):
    """Return JSON for any unexpected exception (helps debugging)."""
    logger.exception("Unhandled exception in service")
    return json_response({
        "error": str(e),
        "type": type(e).__name__
    }, 500)
