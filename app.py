from flask import Flask, render_template, request
from password_engine import analyze_password, PasswordGenerator
from breach_checker import check_breach

app = Flask(__name__)

generator = PasswordGenerator()

print("CI pipeline test")

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":

        # 🔐 GENERATE PASSWORD (Fixed at 100 bits)
        if request.form.get("generate") == "yes":
            generated = generator.generate_password(target_entropy_bits=100)

            return render_template(
                "index.html",
                generated_password=generated["password"]
            )

        # 🔎 ANALYZE PASSWORD
        password = request.form.get("password")

        if not password:
            return render_template("index.html")

        result = analyze_password(password)

        # Clean feedback formatting
        feedback_data = result.get("feedback", {})
        result["warning"] = feedback_data.get("warning", "")
        result["suggestions"] = feedback_data.get("suggestions", [])

        breach_count = None
        if request.form.get("breach_check") == "yes":
            breach_count = check_breach(password)

        return render_template(
            "result.html",
            result=result,
            breach_count=breach_count
        )

    return render_template("index.html")


if __name__ == "__main__":
    app.run(debug=True)