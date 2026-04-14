import os

from app import app


if __name__ == "__main__":
    app.run(debug=app.config["FLASK_DEBUG"], port=app.config["APP_PORT"])
