import crypto_utils
import storage


def ensure_authorities_initialized():
    authorities = storage.list_tally_authorities()
    if authorities:
        return authorities

    shares = crypto_utils.split_tally_private_key()
    storage.initialize_tally_authorities(shares)
    return storage.list_tally_authorities()


def materialize_threshold_contributions(election_id, tally_fingerprint, aggregated_ciphertexts, threshold):
    authorities = ensure_authorities_initialized()
    selected_authorities = authorities[:threshold]

    for option_index, ciphertext in enumerate(aggregated_ciphertexts):
        for authority in selected_authorities:
            partial_value_hex = crypto_utils.compute_partial_decryption(
                ciphertext,
                int(authority["share_value_hex"], 16),
            )
            signature_hex = crypto_utils.sign_partial_decryption(
                authority["authority_index"],
                tally_fingerprint,
                option_index,
                partial_value_hex,
            )
            storage.record_partial_decryption(
                election_id,
                tally_fingerprint,
                option_index,
                authority["authority_name"],
                partial_value_hex,
                signature_hex,
            )

    return authorities


def collect_threshold_session(election_id, tally_fingerprint):
    partial_rows = storage.list_partial_decryptions(election_id, tally_fingerprint) if tally_fingerprint else []
    authorities = ensure_authorities_initialized()
    authority_by_name = {
        authority["authority_name"]: authority
        for authority in authorities
    }

    proof_artifacts = []
    partial_by_option = {}
    for row in partial_rows:
        authority = authority_by_name.get(row["authority_name"])
        signature_valid = False
        if authority:
            signature_valid = crypto_utils.verify_partial_decryption_signature(
                authority["authority_index"],
                tally_fingerprint,
                row["option_index"],
                row["partial_value_hex"],
                row["signature_hex"],
            )
        proof_artifacts.append(
            {
                "authority_name": row["authority_name"],
                "authority_index": authority["authority_index"] if authority else None,
                "option_index": row["option_index"],
                "partial_value_hex": row["partial_value_hex"],
                "signature_hex": row["signature_hex"],
                "signature_valid": signature_valid,
            }
        )
        if signature_valid:
            partial_by_option.setdefault(row["option_index"], []).append(row)

    authority_status = []
    for authority in authorities:
        contributions = [
            artifact for artifact in proof_artifacts
            if artifact["authority_name"] == authority["authority_name"]
        ]
        verified_count = sum(1 for artifact in contributions if artifact["signature_valid"])
        authority_status.append(
            {
                "authority_name": authority["authority_name"],
                "authority_index": authority["authority_index"],
                "public_commitment_hex": authority["public_commitment_hex"],
                "is_active": bool(authority["is_active"]),
                "contributed": bool(contributions),
                "contribution_count": len(contributions),
                "verified_contribution_count": verified_count,
                "public_signing_key_pem": crypto_utils.get_tally_authority_public_key(
                    authority["authority_index"]
                ).public_bytes(
                    encoding=crypto_utils.serialization.Encoding.PEM,
                    format=crypto_utils.serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8"),
            }
        )

    return {
        "authorities": authorities,
        "authority_status": authority_status,
        "proof_artifacts": proof_artifacts,
        "partial_by_option": partial_by_option,
    }


def reconstruct_secret_from_session(session_data, threshold):
    verified_artifacts = [
        artifact for artifact in session_data["proof_artifacts"]
        if artifact["signature_valid"] and artifact["authority_index"] is not None
    ]
    seen = set()
    reconstruction_shares = []
    for artifact in verified_artifacts:
        key = artifact["authority_name"]
        if key in seen:
            continue
        authority = storage.get_tally_authority(artifact["authority_name"])
        if not authority:
            continue
        reconstruction_shares.append(
            {
                "authority_index": authority["authority_index"],
                "share_value": int(authority["share_value_hex"], 16),
            }
        )
        seen.add(key)
        if len(reconstruction_shares) >= threshold:
            break

    if len(reconstruction_shares) < threshold:
        return None

    return crypto_utils.reconstruct_tally_secret_from_shares(reconstruction_shares)
