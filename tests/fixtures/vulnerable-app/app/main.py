import os
import sqlite3

from flask import Flask, request

app = Flask(__name__)

# Hardcoded secret — should be flagged by both Semgrep and Trivy's secret scanner.
API_SECRET_KEY = "hardcoded-do-not-commit-secret-a1b2c3d4e5f6"


@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # SQL injection: user input concatenated directly into the query string.
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return str(conn.execute(query).fetchall())


@app.route("/calc")
def calc():
    expression = request.args.get("expr")
    # Remote code execution: eval() on unsanitized user input.
    result = eval(expression)
    return str(result)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection: unsanitized user input passed to a shell.
    os.system("ping -c 1 " + host)
    return "done"


if __name__ == "__main__":
    # debug=True exposes the Werkzeug interactive debugger — an RCE vector
    # if reachable. Binding to 0.0.0.0 exposes it beyond localhost.
    app.run(debug=True, host="0.0.0.0")
