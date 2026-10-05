from flask import Blueprint, jsonify

bp = Blueprint('broken', __name__)

@bp.route('')                    # пустой URL
def empty():
    return jsonify({})

@bp.route('noslash')             # без слеша
def noslash():
    return jsonify({})

@bp.route('/dup', methods=['GET'])
def dup1():
    return jsonify({})

@bp.route('/dup', methods=['GET'])   # точный дубликат метода+URL
def dup2():
    return jsonify({})

@bp.route('/items/<thing>')      # параметр без типа
def get_thing(thing):
    return jsonify({})
