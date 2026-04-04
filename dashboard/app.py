"""
Flask Application Factory
"""

from flask import Flask
import config


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = config.SECRET_KEY

    @app.context_processor
    def inject_demo_flag():
        return {"demo_mode": config.DEMO_MODE}

    from dashboard.routes import bp
    app.register_blueprint(bp)

    return app
