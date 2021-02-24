from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import sqlite3
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

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

c.execute("""CREATE TABLE IF NOT EXISTS"deceased" (
	"id"	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
	"first name"	TEXT NOT NULL,
    "last name"	TEXT NOT NULL,
	"location"	TEXT NOT NULL,
    "rfb"	TEXT,
	"c/b"	TEXT,
	"viewing"	TEXT,
	"papers"	TEXT,
	"music"	TEXT,
	"sheets"	TEXT,
	"encoffined"	TEXT,
	"clothes"	TEXT,
	"prep"	TEXT
)""")

conn.commit()
conn.close()


def login_required(f):
    """
    Decorate routes to require login.

    http://flask.pocoo.org/docs/1.0/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


@app.route('/')
@login_required
def index():

    conn = sqlite3.connect('mortuus.db')
    c = conn.cursor()

    c.execute("SELECT * FROM deceased")
    deceased = c.fetchall()
    conn.commit()
    conn.close()

    return render_template("index.html", deceased=deceased)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        second_name = request.form.get("second_name")
        location = request.form.get("location")

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute("INSERT INTO main.deceased ('first name', 'last name', 'location') VALUES (?,?,?)",
                  (first_name, second_name, location))
        conn.commit()
        conn.close()

        return redirect("/")

    else:
        return redirect("/")


@app.route('/login', methods=['GET', 'POST'])
def login():

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("login.html", error="Must provide username")

            # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("login.html", error="Must provide password")

        username = request.form.get("username")

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute(
            "SELECT * FROM users WHERE  username = ?", (username,))

        rows = c.fetchall()
        conn.commit()
        conn.close()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return render_template("login.html", error="Invalid username or password")

            # Remember which user has logged in
        session["user_id"] = rows[0][0]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)

    else:
        return render_template("login.html")


"""
@app.route("/register", methods=["GET", "POST"])
def register():
    #Register user

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
        conn.close()
        return redirect("login")

    return render_template("register.html")
"""


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


if __name__ == '__main__':
    app.run(debug=True)

conn.close()
