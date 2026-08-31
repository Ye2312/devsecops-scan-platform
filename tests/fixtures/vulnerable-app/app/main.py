import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

API_SECRET_KEY = "hardcoded-do-not-commit-secret-a1b2c3d4e5f6"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return str(conn.execute(query).fetchall())


@app.route("/calc")
def calc():
    expression = request.args.get("expr")
    result = eval(expression)
    return str(result)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "done"


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
