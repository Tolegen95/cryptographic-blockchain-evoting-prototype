import hashlib
import os
import tempfile
import unittest

import crypto_utils
import service
import storage


class ServiceApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_service.db")
        storage.set_database_path(self.db_path)
        storage.initialize_storage(reset=True)
        service.blockchain = service.load_blockchain()
        service.peers = set()
        self.client = service.app.test_client()
        self.election = storage.get_active_election()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_new_transaction_rejects_missing_fields(self):
        response = self.client.post("/new_transaction", json={})

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Invalid transaction data")

    def test_new_transaction_accepts_registered_voter(self):
        voter_hash = hashlib.sha256("VOID001".encode()).hexdigest()

        response = self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Democratic Party"
            },
        )

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.get_json()["message"], "Success")
        self.assertEqual(len(storage.get_pending_ballots()), 1)

    def test_new_transaction_rejects_double_vote(self):
        voter_hash = hashlib.sha256("VOID001".encode()).hexdigest()
        payload = {
            "election_id": self.election["id"],
            "voter_hash": voter_hash,
            "party": "Democratic Party"
        }

        self.client.post("/new_transaction", json=payload)
        response = self.client.post("/new_transaction", json=payload)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["error"], "Voter has already voted")

    def test_mining_confirms_ballots_and_persists_block(self):
        voter_hash = hashlib.sha256("VOID002".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Republican Party"
            },
        )

        response = self.client.get("/mine")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["index"], 1)
        self.assertEqual(len(storage.load_blocks()), 2)
        self.assertEqual(storage.get_vote_counts(self.election["id"])["Republican Party"], 1)

    def test_results_are_derived_from_chain_not_ballots_for_simple_votes(self):
        voter_hash = hashlib.sha256("VOID002".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Republican Party"
            },
        )
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute(
                """
                UPDATE ballots
                SET selection = 'Democratic Party'
                WHERE election_id = ?
                """,
                (self.election["id"],)
            )
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/results")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"Republican Party": 1})

    def test_invalid_chain_is_detected(self):
        voter_hash = hashlib.sha256("VOID003".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Socialist Party"
            },
        )
        self.client.get("/mine")
        chain_dump = self.client.get("/chain").get_json()["chain"]
        chain_dump[1]["transactions"][0]["party"] = "Tampered"

        self.assertFalse(service.Blockchain.check_chain_validity(chain_dump))

    def test_blind_token_and_encrypted_ballot_flow(self):
        voter_hash = hashlib.sha256("VOID004".encode()).hexdigest()
        blinded = crypto_utils.blind_token_message("b" * 64)

        issue_response = self.client.post(
            "/issue_token",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "blinded_token": blinded["blinded_token"],
            },
        )

        self.assertEqual(issue_response.status_code, 201)
        token_signature = crypto_utils.unblind_signature(
            issue_response.get_json()["blind_signature"],
            blinded["blind_factor"]
        )
        self.assertTrue(crypto_utils.verify_token_signature("b" * 64, token_signature))

        encrypted_ballot = crypto_utils.encrypt_ballot_payload({
            "election_id": self.election["id"],
            "selection": "Democratic Party",
            "nonce": "n1",
        })
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(
            self.election["options"],
            "Democratic Party",
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)

        cast_response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": "b" * 64,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )

        self.assertEqual(cast_response.status_code, 201)
        verify_response = self.client.get("/verify_receipt/{}".format(receipt_hash))
        self.assertEqual(verify_response.status_code, 200)
        self.assertTrue(verify_response.get_json()["found"])

    def test_results_are_derived_from_chain_not_ballots_for_encrypted_votes(self):
        voter_hash = hashlib.sha256("VOID004".encode()).hexdigest()
        blinded = crypto_utils.blind_token_message("b" * 64)

        issue_response = self.client.post(
            "/issue_token",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "blinded_token": blinded["blinded_token"],
            },
        )
        token_signature = crypto_utils.unblind_signature(
            issue_response.get_json()["blind_signature"],
            blinded["blind_factor"]
        )

        encrypted_ballot = crypto_utils.encrypt_ballot_payload({
            "election_id": self.election["id"],
            "selection": "Democratic Party",
            "nonce": "n1",
        })
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(
            self.election["options"],
            "Democratic Party",
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)

        cast_response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": "b" * 64,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )
        self.assertEqual(cast_response.status_code, 201)
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE election_id = ?", (self.election["id"],))
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/results")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"Democratic Party": 1})

    def test_verify_receipt_recovers_confirmed_ballot_view_from_chain(self):
        voter_hash = hashlib.sha256("VOID004".encode()).hexdigest()
        blinded = crypto_utils.blind_token_message("b" * 64)

        issue_response = self.client.post(
            "/issue_token",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "blinded_token": blinded["blinded_token"],
            },
        )
        token_signature = crypto_utils.unblind_signature(
            issue_response.get_json()["blind_signature"],
            blinded["blind_factor"]
        )

        encrypted_ballot = crypto_utils.encrypt_ballot_payload({
            "election_id": self.election["id"],
            "selection": "Democratic Party",
            "nonce": "n1",
        })
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(
            self.election["options"],
            "Democratic Party",
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)

        cast_response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": "b" * 64,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )
        self.assertEqual(cast_response.status_code, 201)
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/verify_receipt/{}".format(receipt_hash))

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["found"])
        self.assertEqual(response.get_json()["status"], "confirmed")

    def test_bulletin_board_is_derived_from_chain(self):
        voter_hash = hashlib.sha256("VOID004".encode()).hexdigest()
        blinded = crypto_utils.blind_token_message("b" * 64)

        issue_response = self.client.post(
            "/issue_token",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "blinded_token": blinded["blinded_token"],
            },
        )
        token_signature = crypto_utils.unblind_signature(
            issue_response.get_json()["blind_signature"],
            blinded["blind_factor"]
        )

        encrypted_ballot = crypto_utils.encrypt_ballot_payload({
            "election_id": self.election["id"],
            "selection": "Democratic Party",
            "nonce": "n1",
        })
        homomorphic_ballot = crypto_utils.build_homomorphic_ballot(
            self.election["options"],
            "Democratic Party",
        )
        receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)

        cast_response = self.client.post(
            "/cast_ballot",
            json={
                "election_id": self.election["id"],
                "token_message": "b" * 64,
                "token_signature": token_signature,
                "encrypted_ballot": encrypted_ballot,
                "receipt_hash": receipt_hash,
                "homomorphic_ballot": homomorphic_ballot,
            },
        )
        self.assertEqual(cast_response.status_code, 201)
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/bulletin_board")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["ballot_view_consistent"])
        self.assertTrue(any(item["receipt_hash"] == receipt_hash for item in payload["items"]))

    def test_homomorphic_results_match_confirmed_ballots(self):
        for voter_id, selection, token_seed in [
            ("VOID001", "Democratic Party", "1" * 64),
            ("VOID002", "Republican Party", "2" * 64),
            ("VOID003", "Democratic Party", "3" * 64),
        ]:
            voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
            blinded = crypto_utils.blind_token_message(token_seed)
            issue_response = self.client.post(
                "/issue_token",
                json={
                    "election_id": self.election["id"],
                    "voter_hash": voter_hash,
                    "blinded_token": blinded["blinded_token"],
                },
            )
            token_signature = crypto_utils.unblind_signature(
                issue_response.get_json()["blind_signature"],
                blinded["blind_factor"],
            )
            encrypted_ballot = crypto_utils.encrypt_ballot_payload({
                "election_id": self.election["id"],
                "selection": selection,
                "nonce": token_seed[:8],
            })
            receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
            homomorphic_ballot = crypto_utils.build_homomorphic_ballot(self.election["options"], selection)
            cast_response = self.client.post(
                "/cast_ballot",
                json={
                    "election_id": self.election["id"],
                    "token_message": token_seed,
                    "token_signature": token_signature,
                    "encrypted_ballot": encrypted_ballot,
                    "receipt_hash": receipt_hash,
                    "homomorphic_ballot": homomorphic_ballot,
                },
            )
            self.assertEqual(cast_response.status_code, 201)

        mine_response = self.client.get("/mine")
        self.assertEqual(mine_response.status_code, 200)

        response = self.client.get("/homomorphic_results")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["ballot_count"], 3)
        self.assertEqual(payload["totals"]["Democratic Party"], 2)
        self.assertEqual(payload["totals"]["Republican Party"], 1)
        self.assertTrue(payload["threshold"]["ready"])
        self.assertEqual(payload["threshold"]["mode"], "shamir_reconstruction_2_of_3")
        self.assertEqual(payload["threshold"]["threshold"], 2)
        self.assertEqual(payload["threshold"]["authority_count"], 3)
        contributed = [authority for authority in payload["threshold"]["authorities"] if authority["contributed"]]
        self.assertEqual(len(contributed), 2)
        self.assertEqual(
            len(payload["threshold"]["proof_artifacts"]),
            payload["threshold"]["threshold"] * len(payload["options"]),
        )
        self.assertTrue(all(proof["signature_valid"] for proof in payload["threshold"]["proof_artifacts"]))

    def test_homomorphic_results_recover_confirmed_ballots_from_chain(self):
        for voter_id, selection, token_seed in [
            ("VOID001", "Democratic Party", "1" * 64),
            ("VOID002", "Republican Party", "2" * 64),
        ]:
            voter_hash = hashlib.sha256(voter_id.encode()).hexdigest()
            blinded = crypto_utils.blind_token_message(token_seed)
            issue_response = self.client.post(
                "/issue_token",
                json={
                    "election_id": self.election["id"],
                    "voter_hash": voter_hash,
                    "blinded_token": blinded["blinded_token"],
                },
            )
            token_signature = crypto_utils.unblind_signature(
                issue_response.get_json()["blind_signature"],
                blinded["blind_factor"],
            )
            encrypted_ballot = crypto_utils.encrypt_ballot_payload({
                "election_id": self.election["id"],
                "selection": selection,
                "nonce": token_seed[:8],
            })
            receipt_hash = crypto_utils.ballot_receipt_hash(encrypted_ballot)
            homomorphic_ballot = crypto_utils.build_homomorphic_ballot(self.election["options"], selection)
            cast_response = self.client.post(
                "/cast_ballot",
                json={
                    "election_id": self.election["id"],
                    "token_message": token_seed,
                    "token_signature": token_signature,
                    "encrypted_ballot": encrypted_ballot,
                    "receipt_hash": receipt_hash,
                    "homomorphic_ballot": homomorphic_ballot,
                },
            )
            self.assertEqual(cast_response.status_code, 201)

        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/homomorphic_results")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["ballot_count"], 2)
        self.assertEqual(payload["totals"]["Democratic Party"], 1)
        self.assertEqual(payload["totals"]["Republican Party"], 1)

    def test_integrity_status_reports_repair_of_confirmed_view(self):
        voter_hash = hashlib.sha256("VOID002".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Republican Party"
            },
        )
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/integrity_status")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["chain_valid"])
        self.assertTrue(payload["ballot_view_consistent"])
        self.assertTrue(payload["ballot_view_repaired"])

    def test_rebuild_state_from_chain_restores_confirmed_view(self):
        voter_hash = hashlib.sha256("VOID002".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Republican Party"
            },
        )
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute("DELETE FROM ballots WHERE status = 'confirmed'")
            connection.commit()
        finally:
            connection.close()

        response = self.client.post("/rebuild_state_from_chain")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["message"], "Confirmed ballot view rebuilt from blockchain")
        self.assertEqual(payload["confirmed_ballot_count"], 1)

    def test_result_consistency_detects_derived_view_mismatch(self):
        voter_hash = hashlib.sha256("VOID002".encode()).hexdigest()
        self.client.post(
            "/new_transaction",
            json={
                "election_id": self.election["id"],
                "voter_hash": voter_hash,
                "party": "Republican Party"
            },
        )
        self.client.get("/mine")

        connection = storage.get_connection()
        try:
            connection.execute(
                """
                UPDATE ballots
                SET selection = 'Democratic Party'
                WHERE election_id = ? AND status = 'confirmed'
                """,
                (self.election["id"],)
            )
            connection.commit()
        finally:
            connection.close()

        response = self.client.get("/result_consistency")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["chain_counts"], {"Republican Party": 1})
        self.assertEqual(payload["derived_view_counts"], {"Democratic Party": 1})
        self.assertFalse(payload["counts_match"])

    def test_any_two_threshold_shares_reconstruct_tally_secret(self):
        shares = crypto_utils.split_tally_private_key(share_count=3, threshold=2)
        expected_secret = crypto_utils.get_tally_private_key() % crypto_utils.HOMOMORPHIC_PRIME

        for pair in [(0, 1), (0, 2), (1, 2)]:
            reconstructed = crypto_utils.reconstruct_tally_secret_from_shares(
                [shares[pair[0]], shares[pair[1]]]
            )
            self.assertEqual(reconstructed, expected_secret)

    def test_scrypt_pin_hash_roundtrip_and_legacy_compatibility(self):
        pin = "4821"
        modern_hash = storage.hash_pin(pin)
        legacy_compatible_hash = modern_hash.replace(
            modern_hash.rsplit("$", 1)[0] + "$",
            modern_hash.rsplit("$", 1)[0] + "$$",
            1,
        )

        self.assertTrue(storage.verify_pin(pin, modern_hash))
        self.assertTrue(storage.verify_pin(pin, legacy_compatible_hash))
        self.assertFalse(storage.verify_pin("0000", modern_hash))


if __name__ == "__main__":
    unittest.main()
