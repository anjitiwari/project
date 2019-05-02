from flaskblog import app

db=SQLAlchemy(app)


if __name__ == "__main__":
    app.run(debug=True)