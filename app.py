from flask import Flask, render_template, request, jsonify
from password_check import custom_password_req
from flask_cors import CORS

app = Flask(__name__)   
CORS(app)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/custom_password", methods=["POST"])
def custom_password():
    data = request.get_json(force=True)
    password = data["id_password"]
    result = str(custom_password_req(password)).lower()
    return jsonify(
            {
                "code": 201,
                "data": result,
                "message": "Success"
            }
    ), 201
    
if __name__ == "__main__":
    app.run(debug=True)