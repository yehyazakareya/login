import os
import re
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")



@app.route("/")
@login_required
def index():
    ls = list()
    total = list()
    table = db.execute("SELECT stock, name, shares FROM purchase WHERE user = :user ", user=session["user_id"])
    for prices in table:
        stock = lookup(prices["stock"])
        price = stock["price"]
        ls.append(price)
        v = prices["shares"] * price
        total.append(v)
    cash = db.execute("SELECT cash FROM users WHERE id = :id",
                          id=session["user_id"])
    return render_template("index.html", table=table, ls=ls, total=total, cash=cash)

if __name__ == "__main__":
    app.run()#(debug=False,host='0.0.0.0')



@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    q = True
    if request.method == "GET":
        return render_template("buy.html")
    else:
        if not request.form.get("symbol") or not request.form.get("shares"):
            return apology("symbol or shares is blank")
        share = int(request.form.get("shares"))
        symbol = request.form.get("symbol")
        if share < 0:
            return apology("write positive number")
        stock = lookup(request.form.get("symbol"))
        if stock == None:
            return apology("Symbol doesn't exist")
        price = stock["price"] * share
        cost = stock["price"]
        date = datetime.now()
        cash = db.execute("SELECT cash FROM users WHERE id = :id",
                          id=session["user_id"])
        money = int(cash[0]["cash"])
        if price > money:
            return apology("you don't have enough money")
        check = db.execute("SELECT stock FROM purchase WHERE user = :user", user=session["user_id"])
        db.execute("INSERT INTO buy (user, symbol, shares, price, date) values(:user, :symbol, :shares, :price, :date)", user=session["user_id"], symbol=request.form.get("symbol"), shares=request.form.get("shares"), price=cost, date=date)
        if not check:
            db.execute("INSERT INTO purchase (user, stock, shares, name) values(:user, :stock, :shares, :name)", user=session["user_id"], stock=request.form.get("symbol"), shares=request.form.get("shares"), name=stock["name"])
            db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=money-price, id=session["user_id"])

        else:
            for i in check:
                if i["stock"] == symbol :
                    q = False
            if q == True:
                db.execute("INSERT INTO purchase (user, stock, shares, name) values(:user, :stock, :shares, :name)", user=session["user_id"], stock=request.form.get("symbol"), shares=request.form.get("shares"), name=stock["name"])
                db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=money-price, id=session["user_id"])
            else:
                x = db.execute("SELECT shares FROM purchase WHERE stock = :stock", stock=request.form.get("symbol"))
                for z in x:
                    db.execute("UPDATE purchase SET shares = :shares WHERE stock = :stock AND user = :user", shares = z["shares"] + share, stock=request.form.get("symbol"), user=session["user_id"])
                    db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=money-price, id=session["user_id"])

        return redirect("/")
@app.route("/history")
@login_required
def history():
    tab1 = db.execute("SELECT * FROM buy WHERE user = :user ORDER BY date", user=session["user_id"])
    tab2 = db.execute("SELECT * FROM sell WHERE user = :user ORDER BY date", user=session["user_id"])
    return render_template("history.html", tab1=tab1, tab2=tab2)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        y = lookup(request.form.get("Symbol"))
        if y == None:
            return("Symbol doesn't exist")
        else:
            return render_template("quoted.html", y=y)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    ls = re.compile('[@_!#$%&*?~:]')
    if request.method == "POST":
        if not request.form.get("user"):
            return apology("You must provide a username")
        user = request.form.get("user")
        names = db.execute("SELECT username FROM users ")
        for name in names:
            if  name["username"] == user:
                return apology("The username is already taken")

        if not request.form.get("pass") == request.form.get("passconfirm"):
            return apology("sorry, your passwords didn't match")

        if not request.form.get("pass"):
            return apology("You must provide password")

        if not request.form.get("passconfirm"):
            return apology("You must provide password")
        pas = request.form.get("pass")
        if len(pas) < 6:
            return apology("your password should be at least 6 characters")
        if ls.search(pas) == None:
            return apology("your password must contain one or more of these characters: @ _ ! # $ % & * ? ~ : ")
        if re.search('[a-zA-Z]', pas) == None:
            return apology ("your password must contain letters")
        password = generate_password_hash(request.form.get("pass"))
        username = request.form.get("user")
        db.execute("INSERT INTO users (username, hash) values(:username, :password)", username=username, password=password)
        return render_template("login.html")
    else:
        return render_template("register.html")



@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        stocks = db.execute("SELECT stock FROM purchase WHERE user = :user ", user=session["user_id"])
        return render_template("sell.html", stocks=stocks)
    else:
        if not request.form.get("shares"):
            return apology(" shares is blank")
        share = int(request.form.get("shares"))
        if share < 0 :
            return apology("write positive number")
        shares = db.execute("SELECT shares FROM purchase WHERE user = :user AND stock = :stock", user=session["user_id"], stock=request.form.get("stock"))
        for i in shares:
            if share > i["shares"]:
                return apology("Too many shares")
        stock = lookup(request.form.get("stock"))
        price = stock["price"] * share
        cost = stock["price"]
        date = datetime.now()
        cash = db.execute("SELECT cash FROM users WHERE id = :id",
                          id=session["user_id"])
        money = int(cash[0]["cash"])
        db.execute("INSERT INTO sell (user, symbol, shares, price, date) values(:user, :symbol, :shares, :price, :date)", user=session["user_id"], symbol=request.form.get("stock"), shares="-" + request.form.get("shares"), price=cost, date=date)
        x = db.execute("SELECT shares FROM purchase WHERE stock = :stock", stock=request.form.get("stock"))
        for z in x:
            db.execute("UPDATE purchase SET shares = :shares WHERE stock = :stock AND user = :user", shares = z["shares"] - share, stock=request.form.get("stock"), user=session["user_id"])
            db.execute("UPDATE users SET cash = :cash WHERE id = :id", cash=money+price, id=session["user_id"])

        return redirect("/")
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
