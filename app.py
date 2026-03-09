from flask import Flask, render_template, request
from password_engine import analyze_password, PasswordGenerator
from breach_checker import check_breach
import os

app = Flask(__name__)

generator = PasswordGenerator()

print("CI pipeline test")

@app.route("/", methods=["GET", "POST"])
def home():

# Handle POST requests (form submissions)
 if request.method == "POST":

    # 🔐 PASSWORD GENERATION
    if request.form.get("generate") == "yes":
        generated = generator.generate_password(target_entropy_bits=100)

        return render_template(
            "index.html",
            generated_password=generated.get("password")
        )

    # 🔎 PASSWORD ANALYSIS
    password = request.form.get("password")

    # If no password provided, reload page
    if not password:
        return render_template("index.html")

    result = analyze_password(password)

    # Clean feedback formatting
    feedback_data = result.get("feedback", {})
    result["warning"] = feedback_data.get("warning", "")
    result["suggestions"] = feedback_data.get("suggestions", [])

    # 🛡 BREACH CHECK
    breach_count = None
    if request.form.get("breach_check") == "yes":
        breach_count = check_breach(password)

    return render_template(
        "result.html",
        result=result,
        breach_count=breach_count
    )

# Default page load (GET request)
 return render_template("index.html")
 if __name__ == "__main__":
   port = int(os.environ.get("PORT", 8080))
   app.run(host="0.0.0.0", port=port)
