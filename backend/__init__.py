from src.server import app

PORT: int = 8000
HOST_ADDRESS: str = '0.0.0.0'

if __name__ == '__main__':
    app.run(debug=True,host=HOST_ADDRESS, port=PORT)