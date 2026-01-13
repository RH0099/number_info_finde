from flask import Flask, request, jsonify
from engine import classify
from db import save

app = Flask(__name__)

@app.route("/analyze", methods=["POST"])
def analyze():
    num = int(request.json["number"])
    result = classify(num)
    save(result)
    return jsonify(result)

@app.route("/batch", methods=["POST"])
def batch():
    nums = request.json["numbers"]
    results = []
    for n in nums:
        r = classify(int(n))
        save(r)
        results.append(r)
    return jsonify(results)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
