import sqlite3

conn = sqlite3.connect("numbers.db", check_same_thread=False)
cur = conn.cursor()

cur.execute("""
CREATE TABLE IF NOT EXISTS analysis (
    number TEXT,
    entropy REAL,
    id_type TEXT,
    crypto_strength TEXT,
    origin TEXT,
    fraud_flags TEXT
)
""")
conn.commit()

def save(result):
    cur.execute(
        "INSERT INTO analysis VALUES (?,?,?,?,?,?)",
        (
            str(result["number"]),
            result["entropy"],
            result["id_type"],
            result["crypto_strength"],
            result["origin"],
            ",".join(result["fraud_flags"])
        )
    )
    conn.commit()
