from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import sqlite3
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

conn = sqlite3.connect('mortuus.db')
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users (
    'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    'username' TEXT NOT NULL,
    'hash' TEXT NOT NULL   
)""")

conn.commit()


@app.route('/')
def index():
    return 'Hello, World test'


@app.route('/login', methods=['GET', 'POST'])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", error="must provide username")

            # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", error="must provide password")

        username = request.form.get("username")

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE  username = ?", (username,))

        rows = c.fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return render_template("login.html", error="invalid username or password")

            # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)

    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("register.html", error="must provide username")

        if not request.form.get("username") or not request.form.get("password") or not request.form.get("confirmation"):
            return render_template("register.html", error="must fill in all fields")

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        username = request.form.get("username")
        c.execute(
            "SELECT * FROM users WHERE username = ?", (username,))
        rows = c.fetchall()

        # Ensure username was submitted
        if len(rows) == 1:
            return render_template("register.html", error="user already exsists")

        elif not request.form.get("password") == request.form.get("confirmation"):
            return render_template("register.html", error="password didn't match")

        pword = request.form.get("password")
        hash = generate_password_hash(pword)

        c.execute("INSERT INTO users (username, hash) VALUES (?,?)",
                  (username, hash))
        conn.commit()
        return redirect("login")

    return render_template("register.html")


if __name__ == '__main__':
    app.run(debug=True)

conn.close()
