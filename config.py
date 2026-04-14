import os
from datetime import timedelta


def env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


class Config:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    SECRET_KEY = os.environ.get("APP_SECRET_KEY", "dev-secret-key-change-me")
    SESSION_TYPE = "filesystem"
    CONNECTED_SERVICE_ADDRESS = os.environ.get(
        "CONNECTED_SERVICE_ADDRESS",
        "http://127.0.0.1:8000"
    )
    SHOW_DEMO_CREDENTIALS = env_flag("SHOW_DEMO_CREDENTIALS", default=False)
    REQUEST_TIMEOUT = int(os.environ.get("REQUEST_TIMEOUT", "5"))
    APP_PORT = int(os.environ.get("APP_PORT", "5001"))
    FLASK_DEBUG = env_flag("FLASK_DEBUG", default=False)
    DATABASE_PATH = os.environ.get("APP_DATABASE_PATH", os.path.join(BASE_DIR, "instance", "e_voting.db"))
    VOTERS_FILE_PATH = os.environ.get("APP_VOTERS_FILE", os.path.join(BASE_DIR, "data", "voters.json"))
    ELECTIONS_FILE_PATH = os.environ.get("APP_ELECTIONS_FILE", os.path.join(BASE_DIR, "data", "elections.json"))
    LOG_FILE_PATH = os.environ.get("APP_LOG_FILE", os.path.join(BASE_DIR, "app.log"))
    AUTHORITY_PRIVATE_KEY_PATH = os.environ.get(
        "AUTHORITY_PRIVATE_KEY_PATH",
        os.path.join(BASE_DIR, "instance", "authority_private.pem")
    )
    BALLOT_PRIVATE_KEY_PATH = os.environ.get(
        "BALLOT_PRIVATE_KEY_PATH",
        os.path.join(BASE_DIR, "instance", "ballot_private.pem")
    )
    TALLY_PRIVATE_KEY_PATH = os.environ.get(
        "TALLY_PRIVATE_KEY_PATH",
        os.path.join(BASE_DIR, "instance", "tally_private.key")
    )
    TALLY_AUTHORITY_COUNT = int(os.environ.get("TALLY_AUTHORITY_COUNT", "3"))
    TALLY_THRESHOLD = int(os.environ.get("TALLY_THRESHOLD", "2"))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    SESSION_COOKIE_SECURE = env_flag("SESSION_COOKIE_SECURE", default=False)
    PERMANENT_SESSION_LIFETIME = timedelta(
        minutes=int(os.environ.get("SESSION_LIFETIME_MINUTES", "30"))
    )
    PREFERRED_URL_SCHEME = os.environ.get("PREFERRED_URL_SCHEME", "https")
    FORCE_HTTPS = env_flag("FORCE_HTTPS", default=False)
    LOGIN_RATE_LIMIT_ATTEMPTS = int(os.environ.get("LOGIN_RATE_LIMIT_ATTEMPTS", "5"))
    LOGIN_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("LOGIN_RATE_LIMIT_WINDOW_SECONDS", "300"))
    LOGIN_RATE_LIMIT_BLOCK_SECONDS = int(os.environ.get("LOGIN_RATE_LIMIT_BLOCK_SECONDS", "600"))
    VOTE_RATE_LIMIT_ATTEMPTS = int(os.environ.get("VOTE_RATE_LIMIT_ATTEMPTS", "3"))
    VOTE_RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("VOTE_RATE_LIMIT_WINDOW_SECONDS", "120"))
    VOTE_RATE_LIMIT_BLOCK_SECONDS = int(os.environ.get("VOTE_RATE_LIMIT_BLOCK_SECONDS", "300"))
    AUDIT_EVENT_LIMIT = int(os.environ.get("AUDIT_EVENT_LIMIT", "100"))
