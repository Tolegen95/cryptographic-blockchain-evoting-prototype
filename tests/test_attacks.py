import hashlib
import os
import tempfile
import unittest

import crypto_utils
import service
import storage


class AttackScenarioTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "attack_tests.db")
        storage.set_database_path(self.db_path)
        storage.initialize_storage(reset=True)
        service.blockchain = service.load_blockchain()
        service.peers = set()
        self.client = service.app.test_client()
        self.election = storage.get_active_election()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _issue_token(self, voter_id, token_message):
        voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
        blinded = crypto_utils.blind_token_message(token_message)
        response = self.client.post(
            "/issue_token",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "blinded_token": blinded["blinded_token"],
            },
        )
        self.assertEqual(response.status_code, 201)
        blind_signature = response.get_json()["blind_signature"]
        token_signature = crypto_utils.unblind_signature(blind_signature, blinded["blind_factor"])
        return voter_hash, token_signature

    def _cast_encrypted_ballot(self, token_message, token_signature, selection):
        encrypted_ballot = crypto_utils.encrypt_ballot_payload(
            {
                "election_id": self.election["id"],
                "selection": selection,
                "nonce": "attack-case",
            }
        )
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(self.election["options"], selection)
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
        response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": token_message,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )
        return response, receipt_hash, encrypted_ballot

    def test_double_voting_is_blocked(self):
        voter_hash = hashlib.sha256("VOID001".encode()).hexdigest()
        payload = {
            "election_id": self.election["id"],
            "voter_hash": voter_hash,
            "party": "Democratic Party",
        }
        self.client.post("/new_transaction", json=payload)
        response = self.client.post("/new_transaction", json=payload)
        self.assertEqual(response.status_code, 400)

    def test_replay_of_anonymous_token_is_blocked(self):
        token_message = "r" * 64
        _, token_signature = self._issue_token("VOID002", token_message)
        first_response, _, _ = self._cast_encrypted_ballot(token_message, token_signature, "Republican Party")
        second_response, _, _ = self._cast_encrypted_ballot(token_message, token_signature, "Republican Party")

        self.assertEqual(first_response.status_code, 201)
        self.assertEqual(second_response.status_code, 400)
        self.assertEqual(second_response.get_json()["error"], "Anonymous token already spent")

    def test_tampered_receipt_hash_is_detected(self):
        token_message = "s" * 64
        _, token_signature = self._issue_token("VOID003", token_message)
        encrypted_ballot = crypto_utils.encrypt_ballot_payload(
            {
                "election_id": self.election["id"],
                "selection": "Socialist Party",
                "nonce": "tamper",
            }
        )
        response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": token_message,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": "0" * 64,
                "homomorphic_ballot": crypto_utils.build_homomorphic_ballot(self.election["options"], "Socialist Party"),
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Receipt hash mismatch")

    def test_deanonymization_is_not_directly_possible_from_bulletin_board(self):
        token_message = "t" * 64
        voter_hash, token_signature = self._issue_token("VOID004", token_message)
        response, receipt_hash, _ = self._cast_encrypted_ballot(token_message, token_signature, "Democratic Party")
        self.assertEqual(response.status_code, 201)
        bulletin = self.client.get("/bulletin_board").get_json()["items"]

        self.assertTrue(any(item["receipt_hash"] == receipt_hash for item in bulletin))
        serialized = str(bulletin)
        self.assertNotIn(voter_hash, serialized)
        self.assertNotIn("VOID004", serialized)

    def test_node_failure_surface_is_observable(self):
        service.peers = {"http://127.0.0.1:65530/"}
        result = service.consensus()
        self.assertFalse(result)

    def test_malformed_homomorphic_ballot_is_rejected(self):
        token_message = "u" * 64
        _, token_signature = self._issue_token("VOID001", token_message)
        encrypted_ballot = crypto_utils.encrypt_ballot_payload(
            {
                "election_id": self.election["id"],
                "selection": "Democratic Party",
                "nonce": "homomorphic",
            }
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
        malformed = crypto_utils.build_homomorphic_ballot(self.election["options"], "Republican Party")
        response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": token_message,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": malformed,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Homomorphic ballot proof mismatch")

    def test_tampered_homomorphic_validity_proof_is_rejected(self):
        token_message = "w" * 64
        _, token_signature = self._issue_token("VOID002", token_message)
        encrypted_ballot = crypto_utils.encrypt_ballot_payload(
            {
                "election_id": self.election["id"],
                "selection": "Republican Party",
                "nonce": "proof-tamper",
            }
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(self.election["options"], "Republican Party")
        homomorphic_ballot["validity_proofs"][0]["challenge"] = "0"

        response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": token_message,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Homomorphic ballot proof mismatch")

    def test_tampered_threshold_proof_is_detected(self):
        token_message = "v" * 64
        _, token_signature = self._issue_token("VOID001", token_message)
        response, _, _ = self._cast_encrypted_ballot(token_message, token_signature, "Democratic Party")
        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.client.get("/mine").status_code, 200)

        first_payload = self.client.get("/homomorphic_results").get_json()
        self.assertTrue(first_payload["threshold"]["ready"])

        connection = storage.get_connection()
        try:
            connection.execute(
                """
                UPDATE tally_partial_decryptions
                SET signature_hex = ?
                WHERE id = (
                    SELECT id FROM tally_partial_decryptions
                    ORDER BY id
                    LIMIT 1
                )
                """,
                ("00" * 64,),
            )
            connection.commit()
        finally:
            connection.close()

        second_payload = self.client.get("/homomorphic_results").get_json()
        self.assertFalse(second_payload["threshold"]["ready"])
        self.assertEqual(second_payload["totals"], {})
        self.assertTrue(any(not proof["signature_valid"] for proof in second_payload["threshold"]["proof_artifacts"]))


if __name__ == "__main__":
    unittest.main()
