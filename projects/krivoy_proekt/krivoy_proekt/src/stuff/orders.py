from flask import Flask, request, jsonify
app = Flask(__name__)

def get_data():
    return request.get_json()

@app.route("/orders", methods=["POST"])
def create_order():
    data = get_data()              # тело из вызова другой функции
    item = data["item"]
    qty = data["quantity"]
    return jsonify({"ok": True})

# URL и методы из словаря
routes_config = {"path": "/config", "methods": ["GET", "PUT"]}
@app.route(routes_config["path"], methods=routes_config["methods"])
def config_handler():
    return jsonify({})
