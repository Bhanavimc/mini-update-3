from flask_migrate import Migrate
from app import create_app, db  # Ensure `db` is imported from your app
import os

app = create_app()

# Initialize Flask-Migrate
migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(debug=True)
