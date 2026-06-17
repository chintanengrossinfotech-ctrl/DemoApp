from app import create_app, init_db
if __name__ == "__main__":
    init_db()
    create_app().run(debug=True, port=5001)
