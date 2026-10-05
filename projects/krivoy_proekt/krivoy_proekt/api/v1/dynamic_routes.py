from flask import Flask, jsonify
app = Flask(__name__)

# роуты генерируются в цикле — джун прочитал на стековерфлоу
for res in ["cats", "dogs", "birds"]:
    app.add_url_rule("/" + res, res, lambda: jsonify([]), methods=["GET"])

# ещё и через enumerate
endpoints = {"products": ["GET"], "orders": ["GET", "POST"]}
for name, methods in endpoints.items():
    app.add_url_rule("/" + name, name, lambda: jsonify([]), methods=methods)
