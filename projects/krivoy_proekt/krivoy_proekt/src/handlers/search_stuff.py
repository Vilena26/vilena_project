from flask import Blueprint, request, jsonify

search_bp = Blueprint('search', __name__)

@search_bp.route("/search")
def search():
    q = request.args.get("q")
    page = request.args["page"]           # через скобки
    limit = request.values.get("limit")   # values вместо args
    sort = request.form.get("sort")       # form
    return jsonify({})

# метод в нижнем регистре
@search_bp.route("/legacy", methods=["get", "post"])
def legacy():
    return jsonify({})
