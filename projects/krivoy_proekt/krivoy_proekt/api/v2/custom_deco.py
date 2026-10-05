from flask import Flask, jsonify
app = Flask(__name__)

def my_route(path):
    def wrapper(f):
        return app.route(path)(f)
    return wrapper

@my_route("/custom")
def custom_endpoint():
    return jsonify({})

@my_route("/another")
def another_one():
    return jsonify({})
