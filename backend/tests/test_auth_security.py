from __future__ import annotations

import unittest
import uuid

from fastapi import HTTPException

from backend.api.auth import create_access_token, hash_password, normalize_email, verify_password, _decode_jwt


class AuthSecurityTests(unittest.TestCase):
    def test_password_hash_is_not_plaintext_and_verifies(self) -> None:
        password = "ChangeMe123!"

        password_hash = hash_password(password)

        self.assertNotEqual(password_hash, password)
        self.assertTrue(verify_password(password, password_hash))
        self.assertFalse(verify_password("wrong-password", password_hash))

    def test_session_token_contains_user_and_organization_claims(self) -> None:
        user_id = uuid.uuid4()
        organization_id = uuid.uuid4()

        token = create_access_token(user_id, organization_id)
        payload = _decode_jwt(token)

        self.assertEqual(payload["sub"], str(user_id))
        self.assertEqual(payload["org_id"], str(organization_id))
        self.assertIn("exp", payload)

    def test_invalid_email_is_rejected(self) -> None:
        with self.assertRaises(HTTPException):
            normalize_email("not-an-email")


if __name__ == "__main__":
    unittest.main()
