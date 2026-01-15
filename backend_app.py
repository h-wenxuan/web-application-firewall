# Real app, handles login, signup and admin
from flask import Flask, request, render_template, redirect, url_for, session

app = Flask(__name__, template_folder="frontend")
app.secret_key = "super-secret-key"  # must be AFTER app creation

# Simple in-memory user database (lab only)
users = {
    "admin": "admin",
    "user": "user"
}

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    show_signup_button = False
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username not in users:
            error = "User not found. Do you want to sign up?"
            show_signup_button = True
        elif users[username] != password:
            error = "Username or password is incorrect"
        else:
            # ✅ STORE LOGIN STATE
            session["username"] = username

            if username == "admin":
                return redirect(url_for("admin_page"))
            else:
                return redirect(url_for("user_page"))

    return render_template("login.html", error=error, show_signup_button=show_signup_button)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None
    success = None

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username in users:
            error = "Username already exists"
        else:
            users[username] = password
            success = "Signup successful! You can now login."

    return render_template("signup.html", error=error, success=success)


@app.route("/admin")
def admin_page():
    # ✅ ADMIN ACCESS CONTROL
    if session.get("username") != "admin":
        return "Unauthorized", 401

    return "<h1>Welcome Admin!</h1>"


@app.route("/user")
def user_page():
    # ✅ USER ACCESS CONTROL
    if "username" not in session:
        return "Unauthorized", 401

    return "<h1>Welcome User!</h1>"


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/vuln_login", methods=["POST"])
def vuln_login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # ❌ INTENTIONALLY vulnerable logic (LAB ONLY)
    if "or" in username.lower():
        return redirect("/admin")

    return "Login failed", 401


if __name__ == "__main__":
    app.run(port=5001, debug=True)
