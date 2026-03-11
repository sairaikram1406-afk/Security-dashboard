from flask import Flask, render_template, request
from password_engine import analyze_password, PasswordGenerator
from breach_checker import check_breach

app = Flask(__name__)

generator = PasswordGenerator()


@app.route("/", methods=["GET", "POST"])
def index():

    generated_password = None
    result = None
    breach_count = None

    if request.method == "POST":

        generate_flag = request.form.get("generate")
        password = request.form.get("password")
        breach_check = request.form.get("breach_check")

        # ---------- GENERATE PASSWORD ----------
        if generate_flag == "yes":
            generated = generator.generate_password(target_entropy_bits=100)
            generated_password = generated["password"]

            return render_template(
                "index.html",
                generated_password=generated_password
            )

        # ---------- ANALYZE PASSWORD ----------
        if password:

            result_data = analyze_password(password)

            result = {
                "score": result_data["score"],
                "guesses": result_data["guesses"],
                "crack_time": result_data["crack_time"],
                "warning": result_data["feedback"]["warning"],
                "suggestions": result_data["feedback"]["suggestions"]
            }

            # ---------- BREACH CHECK ----------
            if breach_check == "yes":
                breach_count = check_breach(password)

            return render_template(
                "result.html",
                result=result,
                breach_count=breach_count
            )

    return render_template(
        "index.html",
        generated_password=generated_password)