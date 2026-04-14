import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import crypto_utils
import requests
from app import app
import storage


class WebAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_web.db")
        storage.set_database_path(self.db_path)
        storage.initialize_storage(reset=True)
        app.config["TESTING"] = True
        app.config["LOGIN_RATE_LIMIT_ATTEMPTS"] = 2
        app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"] = 300
        app.config["LOGIN_RATE_LIMIT_BLOCK_SECONDS"] = 300
        app.config["VOTE_RATE_LIMIT_ATTEMPTS"] = 2
        app.config["VOTE_RATE_LIMIT_WINDOW_SECONDS"] = 300
        app.config["VOTE_RATE_LIMIT_BLOCK_SECONDS"] = 300
        self.client = app.test_client()
        self.election = storage.get_active_election()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _set_session(self, voter_id=None, csrf_token="token123"):
        with self.client.session_transaction() as session:
            session["csrf_token"] = csrf_token
            if voter_id:
                session["voter_id"] = voter_id
                voter = storage.get_voter(voter_id)
                session["role"] = voter["role"] if voter else "voter"

    def test_login_requires_csrf_token(self):
        response = self.client.post(
            "/login",
            data={"voter_id": "VOID001", "pin": "1593"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid or missing CSRF token.", response.data)

    def test_login_succeeds_with_valid_csrf_and_credentials(self):
        self._set_session()

        response = self.client.post(
            "/login",
            data={"csrf_token": "token123", "voter_id": "VOID001", "pin": "1593"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers["Location"].endswith("/"))

    def test_login_rate_limiting_blocks_repeated_failures(self):
        self._set_session()

        self.client.post(
            "/login",
            data={"csrf_token": "token123", "voter_id": "VOID001", "pin": "0000"},
            follow_redirects=False,
        )
        response = self.client.post(
            "/login",
            data={"csrf_token": "token123", "voter_id": "VOID001", "pin": "0000"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Invalid Voter ID or PIN.", response.data)

        response = self.client.post(
            "/login",
            data={"csrf_token": "token123", "voter_id": "VOID001", "pin": "0000"},
            follow_redirects=True,
        )
        self.assertIn(b"Too many login attempts. Try again later.", response.data)

    @patch("app.views.requests.get")
    @patch("app.views.requests.post")
    def test_vote_submit_requires_csrf_and_does_not_call_node(self, mock_post, mock_get):
        self._set_session(voter_id="VOID001")

        response = self.client.post(
            "/submit",
            data={"party": "Democratic Party"},
            follow_redirects=False,
        )

        self.assertEqual(response.status_code, 302)
        mock_post.assert_not_called()
        mock_get.assert_not_called()

    @patch("app.views.requests.get")
    @patch("app.views.requests.post")
    def test_vote_submit_uses_json_api_responses(self, mock_post, mock_get):
        self._set_session(voter_id="VOID001")

        token_message = "c" * 64
        blinded = crypto_utils.blind_token_message(token_message)
        blind_signature = crypto_utils.sign_blinded_token(blinded["blinded_token"])
        token_signature = crypto_utils.unblind_signature(blind_signature, blinded["blind_factor"])
        with self.client.session_transaction() as session:
            session["anonymous_token"] = {
                "token_message": token_message,
                "token_signature": token_signature,
                "token_fingerprint": crypto_utils.token_fingerprint(token_message),
                "election_id": self.election["id"],
            }

        mock_post.return_value = Mock(
            status_code=201,
            json=lambda: {"receipt_hash": "d" * 64, "token_fingerprint": "e" * 64},
        )
        mock_get.side_effect = [
            Mock(status_code=200, json=lambda: {"message": "Block #1 is mined.", "index": 1}),
            Mock(status_code=200, json=lambda: {"chain": [], "length": 0, "peers": []}),
            Mock(status_code=200, json=lambda: []),
            Mock(status_code=200, json=lambda: {"Democratic Party": 1}),
            Mock(status_code=200, json=lambda: {"totals": {"Democratic Party": 1}, "ballot_count": 1, "aggregated_ciphertexts": []}),
            Mock(status_code=200, json=lambda: {"valid": True, "length": 1, "difficulty": 2}),
        ]

        response = self.client.post(
            "/submit",
            data={"csrf_token": "token123", "party": "Democratic Party"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"d" * 64, response.data)
        self.assertIn(b"Block #1 is mined.", response.data)

    @patch("app.views.requests.get")
    def test_verify_vote_shows_confirmed_ballot(self, mock_get):
        self._set_session(voter_id="VOID001")
        receipt_hash = "a" * 64
        storage.create_encrypted_ballot(
            election_id=self.election["id"],
            token_fingerprint="b" * 64,
            encrypted_ballot="ciphertext",
            receipt_hash=receipt_hash,
            token_signature="c" * 10,
            tx_timestamp=1710000000.0,
            selection="Democratic Party",
            status="confirmed",
        )

        mock_get.side_effect = [
            Mock(status_code=200, json=lambda: {"chain": [], "length": 0, "peers": []}),
            Mock(status_code=200, json=lambda: []),
            Mock(status_code=200, json=lambda: {"Democratic Party": 1}),
            Mock(status_code=200, json=lambda: {"totals": {"Democratic Party": 1}, "ballot_count": 1, "aggregated_ciphertexts": []}),
            Mock(status_code=200, json=lambda: {"valid": True, "length": 1, "difficulty": 2}),
            Mock(status_code=200, json=lambda: {"items": [], "valid_chain": True, "length": 1}),
        ]

        response = self.client.post(
            "/verify_vote",
            data={"csrf_token": "token123", "vote_signature": receipt_hash},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Receipt verification completed.", response.data)
        self.assertIn(b"confirmed", response.data)

    @patch("app.views.requests.get")
    def test_verify_vote_page_renders(self, mock_get):
        self._set_session(voter_id="VOID001")
        mock_get.return_value = Mock(status_code=200, json=lambda: {"items": [], "valid_chain": True, "length": 1})

        response = self.client.get("/verify_vote", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Verify receipt inclusion", response.data)

    @patch("app.views.requests.get")
    def test_verify_vote_restores_latest_receipt_after_relogin(self, mock_get):
        self._set_session(voter_id="VOID001")
        receipt_hash = "f" * 64
        voter_hash = storage.hash_voter_id("VOID001")
        storage.issue_anonymous_token(self.election["id"], voter_hash)
        storage.mark_voter_token_spent(self.election["id"], voter_hash, receipt_hash)
        storage.create_encrypted_ballot(
            election_id=self.election["id"],
            token_fingerprint="b" * 64,
            encrypted_ballot="ciphertext",
            receipt_hash=receipt_hash,
            token_signature="c" * 10,
            tx_timestamp=1710000000.0,
            selection="Democratic Party",
            status="confirmed",
        )
        with self.client.session_transaction() as session:
            session.pop("last_receipt_hash", None)

        mock_get.return_value = Mock(status_code=200, json=lambda: {"items": [], "valid_chain": True, "length": 1})

        response = self.client.get("/verify_vote", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(receipt_hash.encode(), response.data)
        self.assertIn(b"confirmed", response.data)

    @patch("app.views.requests.get")
    def test_research_dashboard_renders(self, mock_get):
        self._set_session(voter_id="AUDIT001")
        mock_get.side_effect = [
            Mock(status_code=200, json=lambda: {"chain": [], "length": 1, "peers": []}),
            Mock(status_code=200, json=lambda: []),
            Mock(status_code=200, json=lambda: {"valid": True, "length": 1, "difficulty": 2}),
            Mock(status_code=200, json=lambda: {"totals": {}, "ballot_count": 0, "aggregated_ciphertexts": []}),
            Mock(status_code=200, json=lambda: {"items": [], "valid_chain": True, "length": 1}),
        ]

        response = self.client.get("/research", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Research Dashboard", response.data)

    def test_security_model_renders(self):
        self._set_session(voter_id="AUDIT001")

        response = self.client.get("/security_model", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Model", response.data)

    def test_defense_demo_renders(self):
        self._set_session(voter_id="AUDIT001")

        response = self.client.get("/defense_demo", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Defense Demo", response.data)

    def test_presentation_mode_renders(self):
        self._set_session(voter_id="AUDIT001")

        response = self.client.get("/presentation", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Presentation Mode", response.data)

    @patch("app.views.requests.post")
    def test_issue_token_stores_anonymous_token_in_session(self, mock_post):
        self._set_session(voter_id="VOID001")
        token_message = "f" * 64
        blinded = crypto_utils.blind_token_message(token_message)

        mock_post.return_value = Mock(
            status_code=201,
            json=lambda: {"blind_signature": crypto_utils.sign_blinded_token(blinded["blinded_token"])},
        )

        with patch("app.views.crypto_utils.generate_token_message", return_value=token_message), \
             patch("app.views.crypto_utils.blind_token_message", return_value=blinded):
            response = self.client.post(
                "/issue_token",
                data={"csrf_token": "token123"},
                follow_redirects=False,
            )

        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertIn("anonymous_token", session)

    @patch("app.views.requests.get")
    def test_index_handles_node_unavailable(self, mock_get):
        self._set_session(voter_id="VOID001")
        mock_get.side_effect = requests.RequestException("node unavailable")

        response = self.client.get("/", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Blockchain invalid", response.data)

    def test_auditor_can_access_audit_dashboard(self):
        self._set_session(voter_id="AUDIT001")

        response = self.client.get("/audit", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Audit Dashboard", response.data)
        self.assertIn(b"Result Consistency", response.data)

    def test_auditor_can_filter_audit_dashboard_by_event_type(self):
        self._set_session(voter_id="AUDIT001")
        storage.record_audit_event("custom_test_event", "system", actor_id="tester", details={"ok": True})

        response = self.client.get("/audit?event_type=custom_test_event", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"custom_test_event", response.data)

    def test_auditor_can_filter_audit_dashboard_by_actor_type(self):
        self._set_session(voter_id="AUDIT001")
        storage.record_audit_event("actor_filter_test", "threshold_authority", actor_id="authority-1", details={"share": 1})

        response = self.client.get("/audit?actor_type=threshold_authority", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"threshold_authority", response.data)

    @patch("app.views.requests.post")
    @patch("app.views.requests.get")
    def test_auditor_can_trigger_rebuild_from_audit_dashboard(self, mock_get, mock_post):
        self._set_session(voter_id="AUDIT001")
        mock_get.return_value = Mock(
            status_code=200,
            json=lambda: {
                "chain_valid": True,
                "chain_length": 2,
                "ballot_view_consistent": True,
                "ballot_view_repaired": False,
                "pending_transaction_count": 0,
                "confirmed_encrypted_ballot_count": 1,
                "error": None,
            },
        )
        mock_post.return_value = Mock(
            status_code=200,
            json=lambda: {
                "message": "Confirmed ballot view rebuilt from blockchain",
                "confirmed_ballot_count": 1,
            },
        )

        response = self.client.post(
            "/audit",
            data={
                "csrf_token": "token123",
                "action": "rebuild_state",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Confirmed ballot view rebuilt from blockchain.", response.data)

    def test_admin_can_create_election_from_constructor(self):
        self._set_session(voter_id="ADMIN001")

        response = self.client.post(
            "/audit",
            data={
                "csrf_token": "token123",
                "election_name": "Faculty Council Election",
                "security_profile": "standard",
                "status": "draft",
                "election_options": "Candidate A\nCandidate B\nCandidate C",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Election created successfully.", response.data)
        elections = storage.list_elections()
        self.assertTrue(any(election["name"] == "Faculty Council Election" for election in elections))

    def test_auditor_cannot_create_election(self):
        self._set_session(voter_id="AUDIT001")

        response = self.client.post(
            "/audit",
            data={
                "csrf_token": "token123",
                "election_name": "Unauthorized Election",
                "security_profile": "standard",
                "status": "draft",
                "election_options": "A\nB",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Only admin can create elections.", response.data)

    def test_admin_can_activate_election_and_close_previous_active(self):
        self._set_session(voter_id="ADMIN001")
        created_id = storage.create_election(
            "Municipal Election",
            ["Candidate A", "Candidate B"],
            "standard",
            status="draft",
        )
        previous_active = storage.get_active_election()
        self.assertIsNotNone(previous_active)

        response = self.client.post(
            "/audit",
            data={
                "csrf_token": "token123",
                "action": "set_status",
                "election_id": str(created_id),
                "status": "active",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Election status updated.", response.data)
        active_election = storage.get_active_election()
        self.assertEqual(active_election["id"], created_id)
        old_election = storage.get_election(previous_active["id"])
        self.assertEqual(old_election["status"], "closed")

    def test_admin_can_open_election_designer(self):
        self._set_session(voter_id="ADMIN001")

        response = self.client.get("/admin/elections", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Election Designer", response.data)

    def test_admin_can_edit_draft_election_in_designer(self):
        self._set_session(voter_id="ADMIN001")
        created_id = storage.create_election(
            "Draft Election",
            ["Option A", "Option B"],
            "basic",
            status="draft",
        )

        response = self.client.post(
            "/admin/elections",
            data={
                "csrf_token": "token123",
                "action": "edit",
                "election_id": str(created_id),
                "election_name": "Updated Draft Election",
                "security_profile": "standard",
                "election_options": "Choice 1\nChoice 2\nChoice 3",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Election updated successfully.", response.data)
        election = storage.get_election(created_id)
        self.assertEqual(election["name"], "Updated Draft Election")
        self.assertEqual(election["security_profile"], "standard")
        self.assertEqual(election["options"], ["Choice 1", "Choice 2", "Choice 3"])

    def test_admin_cannot_edit_active_election_in_designer(self):
        self._set_session(voter_id="ADMIN001")
        active = storage.get_active_election()

        response = self.client.post(
            "/admin/elections",
            data={
                "csrf_token": "token123",
                "action": "edit",
                "election_id": str(active["id"]),
                "election_name": "Illegal Update",
                "security_profile": "standard",
                "election_options": "X\nY",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Only draft elections can be edited.", response.data)

    def test_voter_cannot_access_audit_dashboard(self):
        self._set_session(voter_id="VOID001")

        response = self.client.get("/audit", follow_redirects=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Access denied.", response.data)


if __name__ == "__main__":
    unittest.main()
