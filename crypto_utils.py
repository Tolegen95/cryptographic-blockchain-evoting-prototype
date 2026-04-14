import base64
import hashlib
import json
import math
import os
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from config import Config


HOMOMORPHIC_PRIME = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
    "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
    "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E"
    "7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899F"
    "A5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05"
    "98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C"
    "62F356208552BB9ED529077096966D670C354E4ABC9804F174"
    "6C08CA18217C32905E462E36CE3BE39E772C180E86039B2783"
    "A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497C"
    "EA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
HOMOMORPHIC_GENERATOR = 2
TALLY_GROUP_ORDER = HOMOMORPHIC_PRIME - 1


def _ensure_parent_dir(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)


def _generate_rsa_private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _load_or_create_private_key(path):
    _ensure_parent_dir(path)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            return serialization.load_pem_private_key(handle.read(), password=None)

    private_key = _generate_rsa_private_key()
    with open(path, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return private_key


def _load_or_create_ed25519_private_key(path):
    _ensure_parent_dir(path)
    if os.path.exists(path):
        with open(path, "rb") as handle:
            return serialization.load_pem_private_key(handle.read(), password=None)

    private_key = ed25519.Ed25519PrivateKey.generate()
    with open(path, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    return private_key


def get_authority_private_key():
    return _load_or_create_private_key(Config.AUTHORITY_PRIVATE_KEY_PATH)


def get_authority_public_key():
    return get_authority_private_key().public_key()


def get_ballot_private_key():
    return _load_or_create_private_key(Config.BALLOT_PRIVATE_KEY_PATH)


def get_ballot_public_key():
    return get_ballot_private_key().public_key()


def _load_or_create_tally_private_key():
    path = Config.TALLY_PRIVATE_KEY_PATH
    _ensure_parent_dir(path)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip(), 16)

    private_key = secrets.randbelow(HOMOMORPHIC_PRIME - 3) + 2
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(format(private_key, "x"))
    return private_key


def get_tally_private_key():
    return _load_or_create_tally_private_key()


def get_tally_public_key():
    return pow(HOMOMORPHIC_GENERATOR, get_tally_private_key(), HOMOMORPHIC_PRIME)


def _tally_authority_signing_key_path(authority_index):
    return os.path.join(
        Config.BASE_DIR,
        "instance",
        "tally_authority_{}_signing.pem".format(int(authority_index)),
    )


def get_tally_authority_private_key(authority_index):
    return _load_or_create_ed25519_private_key(_tally_authority_signing_key_path(authority_index))


def get_tally_authority_public_key(authority_index):
    return get_tally_authority_private_key(authority_index).public_key()


def split_tally_private_key(share_count=None, threshold=None):
    share_count = share_count or Config.TALLY_AUTHORITY_COUNT
    threshold = threshold or Config.TALLY_THRESHOLD
    if share_count < threshold or threshold < 2:
        raise ValueError("Invalid threshold configuration")

    secret = get_tally_private_key() % HOMOMORPHIC_PRIME
    coefficients = [secret] + [
        secrets.randbelow(HOMOMORPHIC_PRIME - 1) + 1
        for _ in range(threshold - 1)
    ]
    shares = []
    for authority_index in range(1, share_count + 1):
        share_value = 0
        for power, coefficient in enumerate(coefficients):
            share_value = (
                share_value +
                (coefficient * pow(authority_index, power, HOMOMORPHIC_PRIME))
            ) % HOMOMORPHIC_PRIME
        shares.append(
            {
                "authority_index": authority_index,
                "share_value": share_value,
                "public_commitment": pow(HOMOMORPHIC_GENERATOR, share_value, HOMOMORPHIC_PRIME),
            }
        )
    return shares


def reconstruct_tally_secret_from_shares(shares):
    if len(shares) < 2:
        raise ValueError("At least two shares are required for threshold reconstruction")

    secret = 0
    for index, current_share in enumerate(shares):
        x_i = int(current_share["authority_index"]) % HOMOMORPHIC_PRIME
        y_i = int(current_share["share_value"]) % HOMOMORPHIC_PRIME
        numerator = 1
        denominator = 1

        for other_index, other_share in enumerate(shares):
            if other_index == index:
                continue
            x_j = int(other_share["authority_index"]) % HOMOMORPHIC_PRIME
            numerator = (numerator * (-x_j % HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
            denominator = (denominator * ((x_i - x_j) % HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME

        lagrange_basis = (numerator * pow(denominator, -1, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
        secret = (secret + (y_i * lagrange_basis)) % HOMOMORPHIC_PRIME

    return secret


def build_partial_decryption_payload(tally_fingerprint, option_index, partial_value_hex):
    return _canonical_json(
        {
            "tally_fingerprint": tally_fingerprint,
            "option_index": int(option_index),
            "partial_value_hex": partial_value_hex,
        }
    ).encode("utf-8")


def sign_partial_decryption(authority_index, tally_fingerprint, option_index, partial_value_hex):
    payload = build_partial_decryption_payload(tally_fingerprint, option_index, partial_value_hex)
    signature = get_tally_authority_private_key(authority_index).sign(payload)
    return signature.hex()


def verify_partial_decryption_signature(authority_index, tally_fingerprint, option_index, partial_value_hex, signature_hex):
    payload = build_partial_decryption_payload(tally_fingerprint, option_index, partial_value_hex)
    try:
        get_tally_authority_public_key(authority_index).verify(bytes.fromhex(signature_hex), payload)
        return True
    except Exception:
        return False


def export_tally_authority_public_material(authority_count=None):
    authority_count = authority_count or Config.TALLY_AUTHORITY_COUNT
    authorities = []
    for authority_index in range(1, authority_count + 1):
        public_key = get_tally_authority_public_key(authority_index)
        authorities.append(
            {
                "authority_index": authority_index,
                "public_signing_key_pem": public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8"),
            }
        )
    return authorities


def get_authority_public_numbers():
    public_numbers = get_authority_public_key().public_numbers()
    return public_numbers.n, public_numbers.e


def generate_token_message():
    return secrets.token_hex(32)


def token_fingerprint(token_message):
    return hashlib.sha256(token_message.encode("utf-8")).hexdigest()


def _message_to_int(token_message):
    digest = hashlib.sha256(token_message.encode("utf-8")).digest()
    return int.from_bytes(digest, "big")


def blind_token_message(token_message):
    n_value, e_value = get_authority_public_numbers()
    message_int = _message_to_int(token_message)

    while True:
        blind_factor = secrets.randbelow(n_value - 2) + 2
        if math.gcd(blind_factor, n_value) == 1:
            break

    blinded_int = (message_int * pow(blind_factor, e_value, n_value)) % n_value
    return {
        "blinded_token": str(blinded_int),
        "blind_factor": str(blind_factor),
        "message_digest": format(message_int, "x"),
    }


def sign_blinded_token(blinded_token):
    private_numbers = get_authority_private_key().private_numbers()
    blinded_int = int(blinded_token)
    signature_int = pow(blinded_int, private_numbers.d, private_numbers.public_numbers.n)
    return str(signature_int)


def unblind_signature(blind_signature, blind_factor):
    n_value, _ = get_authority_public_numbers()
    signature_int = int(blind_signature)
    factor_inverse = pow(int(blind_factor), -1, n_value)
    unblinded_int = (signature_int * factor_inverse) % n_value
    return str(unblinded_int)


def verify_token_signature(token_message, token_signature):
    n_value, e_value = get_authority_public_numbers()
    signature_int = int(token_signature)
    recovered_int = pow(signature_int, e_value, n_value)
    return recovered_int == _message_to_int(token_message)


def encrypt_ballot_payload(payload):
    plaintext = json.dumps(payload, sort_keys=True).encode("utf-8")
    ciphertext = get_ballot_public_key().encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("ascii")


def decrypt_ballot_payload(ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64.encode("ascii"))
    plaintext = get_ballot_private_key().decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return json.loads(plaintext.decode("utf-8"))


def ballot_receipt_hash(ciphertext_b64):
    return hashlib.sha256(ciphertext_b64.encode("utf-8")).hexdigest()


def _canonical_json(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _hash_ints_to_scalar(*values):
    hasher = hashlib.sha256()
    for value in values:
        if isinstance(value, int):
            encoded = format(value, "x").encode("ascii")
        elif isinstance(value, str):
            encoded = value.encode("utf-8")
        else:
            encoded = _canonical_json(value).encode("utf-8")
        hasher.update(len(encoded).to_bytes(4, "big"))
        hasher.update(encoded)
    return int.from_bytes(hasher.digest(), "big") % TALLY_GROUP_ORDER


def _mod_inverse(value, modulus):
    return pow(value, -1, modulus)


def _encrypt_homomorphic_count_with_randomness(value):
    if value < 0:
        raise ValueError("Homomorphic count must be non-negative")

    randomness = secrets.randbelow(HOMOMORPHIC_PRIME - 3) + 2
    c1 = pow(HOMOMORPHIC_GENERATOR, randomness, HOMOMORPHIC_PRIME)
    c2 = (
        pow(get_tally_public_key(), randomness, HOMOMORPHIC_PRIME) *
        pow(HOMOMORPHIC_GENERATOR, value, HOMOMORPHIC_PRIME)
    ) % HOMOMORPHIC_PRIME
    return {
        "c1": format(c1, "x"),
        "c2": format(c2, "x"),
    }, randomness


def encrypt_homomorphic_count(value):
    ciphertext, _ = _encrypt_homomorphic_count_with_randomness(value)
    return ciphertext


def _chaum_pedersen_prove(base1, base2, target1, target2, witness):
    nonce = secrets.randbelow(TALLY_GROUP_ORDER - 1) + 1
    commitment1 = pow(base1, nonce, HOMOMORPHIC_PRIME)
    commitment2 = pow(base2, nonce, HOMOMORPHIC_PRIME)
    challenge = _hash_ints_to_scalar(
        base1,
        base2,
        target1,
        target2,
        commitment1,
        commitment2,
    )
    response = (nonce + (challenge * witness)) % TALLY_GROUP_ORDER
    return {
        "commitment1": format(commitment1, "x"),
        "commitment2": format(commitment2, "x"),
        "challenge": format(challenge, "x"),
        "response": format(response, "x"),
    }


def _chaum_pedersen_verify(base1, base2, target1, target2, proof):
    commitment1 = int(proof["commitment1"], 16)
    commitment2 = int(proof["commitment2"], 16)
    challenge = int(proof["challenge"], 16)
    response = int(proof["response"], 16)
    expected_challenge = _hash_ints_to_scalar(
        base1,
        base2,
        target1,
        target2,
        commitment1,
        commitment2,
    )
    if challenge != expected_challenge:
        return False

    lhs1 = pow(base1, response, HOMOMORPHIC_PRIME)
    rhs1 = (commitment1 * pow(target1, challenge, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
    lhs2 = pow(base2, response, HOMOMORPHIC_PRIME)
    rhs2 = (commitment2 * pow(target2, challenge, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
    return lhs1 == rhs1 and lhs2 == rhs2


def build_ciphertext_bit_proof(ciphertext, value, randomness):
    if value not in {0, 1}:
        raise ValueError("Bit proof only supports 0 or 1")

    public_key = get_tally_public_key()
    c1 = int(ciphertext["c1"], 16)
    c2 = int(ciphertext["c2"], 16)
    adjusted_c2 = c2
    if value == 1:
        adjusted_c2 = (c2 * _mod_inverse(HOMOMORPHIC_GENERATOR, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME

    proof = _chaum_pedersen_prove(
        HOMOMORPHIC_GENERATOR,
        public_key,
        c1,
        adjusted_c2,
        randomness,
    )
    proof["plaintext_bit"] = value
    return proof


def verify_ciphertext_bit_proof(ciphertext, proof):
    if not isinstance(proof, dict):
        return False
    if proof.get("plaintext_bit") not in {0, 1}:
        return False

    public_key = get_tally_public_key()
    c1 = int(ciphertext["c1"], 16)
    c2 = int(ciphertext["c2"], 16)
    adjusted_c2 = c2
    if proof["plaintext_bit"] == 1:
        adjusted_c2 = (c2 * _mod_inverse(HOMOMORPHIC_GENERATOR, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME

    return _chaum_pedersen_verify(
        HOMOMORPHIC_GENERATOR,
        public_key,
        c1,
        adjusted_c2,
        proof,
    )


def build_ballot_sum_proof(ciphertexts, randomness_values):
    aggregate = aggregate_homomorphic_ciphertexts(ciphertexts)
    aggregate_c1 = int(aggregate["c1"], 16)
    aggregate_c2 = int(aggregate["c2"], 16)
    adjusted_c2 = (aggregate_c2 * _mod_inverse(HOMOMORPHIC_GENERATOR, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
    aggregate_randomness = sum(randomness_values) % TALLY_GROUP_ORDER
    return _chaum_pedersen_prove(
        HOMOMORPHIC_GENERATOR,
        get_tally_public_key(),
        aggregate_c1,
        adjusted_c2,
        aggregate_randomness,
    )


def verify_ballot_sum_proof(ciphertexts, proof):
    aggregate = aggregate_homomorphic_ciphertexts(ciphertexts)
    aggregate_c1 = int(aggregate["c1"], 16)
    aggregate_c2 = int(aggregate["c2"], 16)
    adjusted_c2 = (aggregate_c2 * _mod_inverse(HOMOMORPHIC_GENERATOR, HOMOMORPHIC_PRIME)) % HOMOMORPHIC_PRIME
    return _chaum_pedersen_verify(
        HOMOMORPHIC_GENERATOR,
        get_tally_public_key(),
        aggregate_c1,
        adjusted_c2,
        proof,
    )


def build_homomorphic_ballot(options, selection):
    if selection not in options:
        raise ValueError("Selection is not part of election options")

    ciphertexts = []
    validity_proofs = []
    randomness_values = []
    for option in options:
        value = 1 if option == selection else 0
        ciphertext, randomness = _encrypt_homomorphic_count_with_randomness(value)
        ciphertexts.append(ciphertext)
        validity_proofs.append(build_ciphertext_bit_proof(ciphertext, value, randomness))
        randomness_values.append(randomness)

    return {
        "options": list(options),
        "ciphertexts": ciphertexts,
        "validity_proofs": validity_proofs,
        "sum_proof": build_ballot_sum_proof(ciphertexts, randomness_values),
    }


def homomorphic_ballot_hash(homomorphic_ballot):
    return hashlib.sha256(_canonical_json(homomorphic_ballot).encode("utf-8")).hexdigest()


def aggregate_homomorphic_ciphertexts(ciphertexts):
    aggregate_c1 = 1
    aggregate_c2 = 1
    for ciphertext in ciphertexts:
        aggregate_c1 = (aggregate_c1 * int(ciphertext["c1"], 16)) % HOMOMORPHIC_PRIME
        aggregate_c2 = (aggregate_c2 * int(ciphertext["c2"], 16)) % HOMOMORPHIC_PRIME
    return {
        "c1": format(aggregate_c1, "x"),
        "c2": format(aggregate_c2, "x"),
    }


def compute_partial_decryption(ciphertext, share_value):
    c1 = int(ciphertext["c1"], 16)
    partial = pow(c1, int(share_value), HOMOMORPHIC_PRIME)
    return format(partial, "x")


def combine_partial_decryptions(partial_decryptions):
    # Legacy helper retained for earlier additive-share experiments.
    combined = 1
    for partial in partial_decryptions:
        combined = (combined * int(partial, 16)) % HOMOMORPHIC_PRIME
    return combined


def decrypt_homomorphic_count(ciphertext, max_count, shared_secret=None, secret_exponent=None):
    c2 = int(ciphertext["c2"], 16)
    if shared_secret is None:
        c1 = int(ciphertext["c1"], 16)
        if secret_exponent is None:
            secret_exponent = get_tally_private_key()
        shared_secret = pow(c1, int(secret_exponent), HOMOMORPHIC_PRIME)
    inverse_secret = pow(shared_secret, -1, HOMOMORPHIC_PRIME)
    message_element = (c2 * inverse_secret) % HOMOMORPHIC_PRIME

    current = 1
    for count in range(max_count + 1):
        if current == message_element:
            return count
        current = (current * HOMOMORPHIC_GENERATOR) % HOMOMORPHIC_PRIME

    raise ValueError("Homomorphic ciphertext could not be decrypted in search bound")


def threshold_tally_homomorphic_ballots(serialized_ballots, partial_decryption_sets, max_count):
    if not serialized_ballots:
        return {"options": [], "totals": {}, "aggregated_ciphertexts": []}

    parsed_ballots = []
    for ballot in serialized_ballots:
        parsed_ballot = ballot if isinstance(ballot, dict) else json.loads(ballot)
        parsed_ballots.append(parsed_ballot)

    options = parsed_ballots[0]["options"]
    ciphertext_sets = [ballot["ciphertexts"] for ballot in parsed_ballots]
    aggregated = []
    totals = {}

    for index, option in enumerate(options):
        aggregate = aggregate_homomorphic_ciphertexts([ciphertexts[index] for ciphertexts in ciphertext_sets])
        aggregated.append(aggregate)
        shared_secret = combine_partial_decryptions(partial_decryption_sets[index])
        totals[option] = decrypt_homomorphic_count(aggregate, max_count, shared_secret=shared_secret)

    return {
        "options": options,
        "totals": totals,
        "aggregated_ciphertexts": aggregated,
    }


def tally_homomorphic_ballots(serialized_ballots, max_count):
    if not serialized_ballots:
        return {"options": [], "totals": {}, "aggregated_ciphertexts": []}

    parsed_ballots = []
    for ballot in serialized_ballots:
        parsed_ballot = ballot if isinstance(ballot, dict) else json.loads(ballot)
        parsed_ballots.append(parsed_ballot)

    options = parsed_ballots[0]["options"]
    ciphertext_sets = [ballot["ciphertexts"] for ballot in parsed_ballots]
    aggregated = []
    totals = {}

    for index, option in enumerate(options):
        aggregate = aggregate_homomorphic_ciphertexts([ciphertexts[index] for ciphertexts in ciphertext_sets])
        aggregated.append(aggregate)
        totals[option] = decrypt_homomorphic_count(aggregate, max_count)

    return {
        "options": options,
        "totals": totals,
        "aggregated_ciphertexts": aggregated,
    }


def tally_homomorphic_ballots_with_secret(serialized_ballots, max_count, secret_exponent):
    if not serialized_ballots:
        return {"options": [], "totals": {}, "aggregated_ciphertexts": []}

    parsed_ballots = []
    for ballot in serialized_ballots:
        parsed_ballot = ballot if isinstance(ballot, dict) else json.loads(ballot)
        parsed_ballots.append(parsed_ballot)

    options = parsed_ballots[0]["options"]
    ciphertext_sets = [ballot["ciphertexts"] for ballot in parsed_ballots]
    aggregated = []
    totals = {}

    for index, option in enumerate(options):
        aggregate = aggregate_homomorphic_ciphertexts([ciphertexts[index] for ciphertexts in ciphertext_sets])
        aggregated.append(aggregate)
        totals[option] = decrypt_homomorphic_count(
            aggregate,
            max_count,
            secret_exponent=secret_exponent,
        )

    return {
        "options": options,
        "totals": totals,
        "aggregated_ciphertexts": aggregated,
    }


def export_public_material():
    authority_public = get_authority_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    ballot_public = get_ballot_public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return {
        "authority_public_key_pem": authority_public,
        "ballot_public_key_pem": ballot_public,
        "homomorphic_tally": {
            "prime_hex": format(HOMOMORPHIC_PRIME, "x"),
            "generator_hex": format(HOMOMORPHIC_GENERATOR, "x"),
            "public_key_hex": format(get_tally_public_key(), "x"),
            "authority_count": Config.TALLY_AUTHORITY_COUNT,
            "threshold": Config.TALLY_THRESHOLD,
            "authority_signing_keys": export_tally_authority_public_material(),
        },
    }
