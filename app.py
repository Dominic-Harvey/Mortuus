from flask import Flask, redirect, render_template, request, session
from flask_session import Session
import sqlite3

app = Flask(__name__)

conn = sqlite3.connect('mortuus.db')
c = conn.cursor()

c.execute("""CREATE TABLE users (
    'id' INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    'username' TEXT NOT NULL,
    'hash' TEXT NOT NULL   
)""")

conn.commit()
conn.close()


@app.route('/')
def index():
    return 'Hello, World test'


if __name__ == '__main__':
    app.run(debug=True)
