from flask import Flask, redirect, render_template, request, session, flash, url_for
from flask_session import Session
import sqlite3
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import json
import re

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
    "rfb"   TEXT DEFAULT '',
	"c/b"	TEXT DEFAULT '',
	"viewing"	TEXT DEFAULT '',
	"papers"	TEXT DEFAULT '',
	"music"	TEXT DEFAULT '',
	"sheets"	TEXT DEFAULT '',
	"encoffined"	TEXT DEFAULT '',
	"clothes"	TEXT DEFAULT '',
	"prep"	TEXT DEFAULT ''
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


@app.route('/', methods=['GET'])
@app.route('/<path:branch>', methods=['GET'])
@login_required
def index(branch="All Deceased"):
    if session["search"] == True:
        search = request.args['search']
        session['search'] = False
        branch_names = {
            "0181": "Gordon Barbers Aylsham Road",
            "0956": "Norwich Care Centre",
            "0518": "Gordon Barbers St Williams Way",
            "1049": "Gordon Barbers Eaton",
            "0182": "Gordon Barbers Harvey's",
            "1121": "Gordon Barbers Hoveton"
        }

        if branch in branch_names:
            branch = branch_names[branch] + ' ' + branch

        return render_template("index.html", deceased=json.loads(search), search_active=True, branch=branch)

    conn = sqlite3.connect('mortuus.db')
    c = conn.cursor()

    c.execute("SELECT * FROM deceased ORDER BY `last name`")
    deceased = c.fetchall()
    conn.commit()
    conn.close()

    return render_template("index.html", deceased=deceased, branch=branch)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        location = request.form.get("location")

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute("INSERT INTO main.deceased ('first name', 'last name', 'location') VALUES (?,?,?)",
                  (first_name, last_name, location))
        conn.commit()
        conn.close()

        return redirect("/")

    else:
        return redirect("/")


@app.route('/update', methods=['GET', 'POST'])
@login_required
def update():
    if request.method == "POST":

        deceased_details = ["first_name", "last_name", "location", "rfb", "cb",
                            "viewing", "papers", "music", "sheets", "encoffined", "clothes", "prep", "id"]

        for i, data in enumerate(deceased_details):
            deceased_details[i] = request.form.get(data)
            # if request.form.get(data) == None:
            #    deceased_details[i] = "None"
            if i == 12:
                break

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute("UPDATE main.deceased SET location = ?, rfb = ?, 'c/b' = ?, viewing = ?, papers = ?, music = ?, sheets = ?, encoffined = ?, clothes = ?, prep = ? WHERE id = ?",
                  (deceased_details[2], deceased_details[3], deceased_details[4], deceased_details[5], deceased_details[6], deceased_details[7], deceased_details[8], deceased_details[9], deceased_details[10], deceased_details[11], deceased_details[12]))
        conn.commit()
        conn.close()

        return redirect("/")
    else:
        return redirect("/")


@app.route('/delete', methods=['GET', 'POST'])
@login_required
def delete():
    if request.method == "POST":
        deceased_id = request.form.get("deceased_to_delete")
        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute("DELETE FROM main.deceased WHERE id = ?",
                  (deceased_id))
        conn.commit()
        conn.close()

        return redirect("/")

    else:
        return redirect("/")


@app.route('/search', methods=['GET', 'POST'])
@app.route('/search/<path:branch>', methods=['GET', 'POST'])
@login_required
def search(branch=None):
    if request.method == "POST":

        search = request.form.get("search")
        names = search.split()
        if len(names) == 1:
            names.append(search)

        conn = sqlite3.connect('mortuus.db')
        c = conn.cursor()

        c.execute(
            "SELECT * FROM deceased WHERE `first name` LIKE ? OR `last name` LIKE ? OR `first name` LIKE ? AND `last name` LIKE ? ORDER BY `last name`", (names[0], names[0], names[0], names[1]))
        deceased = c.fetchall()
        session['search'] = True
        search_json = json.dumps(deceased)
        conn.commit()
        conn.close()

        # return render_template("index.html", deceased=deceased)
        return redirect(url_for("index", search=search_json, branch=search))

    else:
        branch_check = re.search("[0-9]{4}$", branch)
        if branch_check != None:
            conn = sqlite3.connect('mortuus.db')
            c = conn.cursor()

            c.execute(
                "SELECT * FROM deceased WHERE location = ? ORDER BY `last name`", (branch,))
            deceased = c.fetchall()
            session['search'] = True
            search = json.dumps(deceased)
            conn.commit()
            conn.close()

            return redirect(url_for("index", search=search, branch=branch))

        return render('/')


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
            "SELECT * FROM users WHERE username = ?", (username,))

        rows = c.fetchall()
        conn.commit()
        conn.close()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0][2], request.form.get("password")):
            return render_template("login.html", error="Invalid username or password")

        # Remember which user has logged in
        session["user_id"] = rows[0][0]
        # Initialises variable for checking if user has perfomred a search
        session['search'] = False

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
