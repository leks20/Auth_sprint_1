from app import app
from utils import create_superuser


if __name__ == "__main__":
    # create_superuser()
    app.run(host="0.0.0.0", debug=True)
