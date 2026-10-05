from flask import *
import json

app = Flask(__name__)

API = "/api"
VERSION = "v1"
default_methods = ["GET", "POST"]

# URL через конкатенацию переменных
@app.route(API + "/" + VERSION + "/users", methods=default_methods)
def users_handler():
    if request.method == "POST":
        d = json.loads(request.data)
        name = d["name"]
        age = d["age"]
        return jsonify({"created": name})
    return jsonify([])

# роут через .format()
@app.route("/user/{}/profile".format("<id>"))
def profile(id):
    return jsonify({"id": id})
