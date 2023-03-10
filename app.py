from flask import Flask, render_template, request, jsonify
from password_check import custom_password_req, guessing_entropy, shannon_entropy, markov_model_entropy, password_suggestion, get_password_strength, get_crack_time, check_password_vulnerabilities
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
    passwordDetails = custom_password_req(password)
    guessingEntropy = guessing_entropy(password)
    shannonEntropy = shannon_entropy(password)
    markovEntropy = markov_model_entropy(password, 2)
    passwordSuggestion = password_suggestion(password)
    passwordStrength = get_password_strength(password)
    passwordCrackTime = get_crack_time(password)
    passwordVulnerabilities = check_password_vulnerabilities(password)
    return jsonify(
            {
                "code": 201,
                "passwordDetails": passwordDetails,
                "guessingEntropy": guessingEntropy,
                "shannonEntropy": shannonEntropy,
                "markovEntropy": markovEntropy,
                "passwordSuggestion": passwordSuggestion,
                "passwordStrength": passwordStrength,
                "passwordCrackTime": passwordCrackTime,
                "passwordVulnerabilities": passwordVulnerabilities,
                "message": "Success"
            }
    ), 201
    
if __name__ == "__main__":
    app.run(debug=True)