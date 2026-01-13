from flask import Flask
import sqlite3

app = Flask(__name__)

@app.route("/")
def home():
    con = sqlite3.connect("numbers.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM analysis ORDER BY rowid DESC LIMIT 20")
    rows = cur.fetchall()

    html = "<h2>Number Intelligence Dashboard</h2><table border=1>"
    html += "<tr><th>Number</th><th>Entropy</th><th>ID Type</th><th>Crypto</th><th>Origin</th><th>Fraud</th></tr>"
    for r in rows:
        html += "<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>"
    html += "</table>"
    return html

if __name__ == "__main__":
    app.run(port=8000)
