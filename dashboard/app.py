"""
Flask Application Factory
"""

from flask import Flask


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "ids-dashboard-secret-change-me"

    from dashboard.routes import bp
    app.register_blueprint(bp)

    return app
