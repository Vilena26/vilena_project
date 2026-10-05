from flask_restful import Resource

class BookApi(Resource):
    def get(self, id):
        return {'book': id}
    def post(self):
        data = self.parse()
        return {'status': 'created'}, 201

class BrokenResource(Resource):
    def helper(self):   # не HTTP-метод
        return 'nope'
