import os
import re
import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from helpers import login_required, tl, sort, validate_email, confirm_pass, format_date
from email.message import EmailMessage
from io import StringIO
from datetime import datetime, timedelta
import bcrypt
import matplotlib.pyplot as plt
import smtplib
import random
import string
import ssl

app = Flask(__name__)
app.jinja_env.filters['tl'] = tl
EMAIL = os.environ.get("EMAIL")
PASSWORD = os.environ.get("PASSWORD")
secret_key = os.urandom(24)
app.secret_key = secret_key
show_chart = False

# Connect to the database
conn = sqlite3.connect("shop.db", check_same_thread=False)
cursor = conn.cursor()

# Configure session to be server-side
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", endpoint="welcome", methods=["GET"])
def welcome():
    if request.method == "GET":
        try:
            user_id = session["user_id"]
        except KeyError:
            return render_template("welcome.html")

        if user_id:
            return redirect(url_for("dashboard"))
        else:
            return render_template("welcome.html")


@app.route("/login", endpoint="login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Eksik bilgi")
            return redirect(url_for("login"))
        
        # Check if user exists
        cursor.execute("SELECT username FROM users")
        rows = cursor.fetchall()
        nameList = []

        # Add all the usernames to the empty list
        if rows:
            i = 0
            while i < len(rows):
                nameList.append(rows[i][0])
                i += 1

            # If username is valid
            if username in nameList:
                cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
                info = cursor.fetchall()
                user = info[0]
                stored_hash = user[1]
                if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
                    session["user_id"] = user[0]
                    flash(f"Hoş geldin, {username}!")
                    return redirect(url_for("dashboard"))
                else:
                    flash("Hatalı parola")
                    return redirect(url_for("login"))
            else:
                flash("Kullanıcı ismi geçersiz")
                return redirect(url_for("login"))

    else:
        return render_template("login.html")
    

@app.route("/forgot_password", endpoint="forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")

        if not username or not email:
            flash("Eksik bilgi")
            return redirect(url_for("forgot_password"))
        
        cursor.execute("SELECT * FROM users WHERE username = ? AND email = ?", (username, email))
        user = cursor.fetchone()

        if user:
            token = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
            expiration = datetime.now() + timedelta(minutes=2)
            cursor.execute("INSERT INTO password_reset_requests (token, expiry_timestamp, user_id) VALUES (?,?,?)", (token, expiration, user[0]))
            conn.commit()
            cursor.execute("SELECT token, expiry_timestamp, id FROM password_reset_requests WHERE user_id = ?", (user[0],))
            token_info = cursor.fetchone()
            print(f"token_info: {token_info}")

            reset_url = url_for('reset_password', token=token, _external=True)
            subject = "Şifre sıfırlama"
            body = f"""
            Şifrenizi sıfırlamak için linke tıklayınız: {reset_url}
            """

            em = EmailMessage()
            em["From"] = EMAIL
            em["To"] = email
            em["Subject"] = subject
            em.set_content(body)

            context = ssl.create_default_context()

            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as smtp:
                smtp.login(EMAIL, PASSWORD)
                smtp.sendmail(EMAIL, email, em.as_string())
            flash("Şifre yenileme talimatları e-posta adresinize gönderildi.")
            return redirect(url_for("forgot_password"))
        
        else:
            flash("Bilgiler geçersiz")
            return redirect(url_for("forgot_password"))
    else:
        return render_template("forgot_password.html")


@app.route("/reset_password/<token>", endpoint="reset_password", methods=["GET", "POST"])
def reset_password(token):
    if request.method == "POST":
        cursor.execute("SELECT id FROM password_reset_requests WHERE token = ? AND expiry_timestamp >= ?", (token, datetime.now()))
        token_id = cursor.fetchone()

        if token_id:
                token_id = token_id[0] # It's indexed after verification to avoid NoneType error
                cursor.execute("SELECT user_id FROM password_reset_requests WHERE id = ?", (token_id,))
                user_id = cursor.fetchone()[0]
                if user_id is None:
                    flash("Geçersiz bilgiler")
                    return redirect(url_for(""))
                new_password = request.form.get("pass")
                confirmation = request.form.get("pass2")
                
                if new_password != confirmation:
                    flash("Şifreler aynı olmalıdır.")
                    return redirect(url_for("welcome"))
                
                if confirm_pass(new_password):
                    hashed_password = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())
                    cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
                    cursor.execute("DELETE FROM password_reset_requests WHERE token = ? AND user_id = ?", (token, user_id))
                    conn.commit()
                    flash("Şifreniz güncellenmiştir.")
                    return redirect(url_for("welcome"))
                else:
                    return redirect(url_for("welcome"))
        else:
            # Token has expired
            flash("Şifre değiştirme talebinizin süresi doldu.")
            return redirect(url_for("welcome"))
        
    else:
        cursor.execute("SELECT id FROM password_reset_requests WHERE token = ? AND expiry_timestamp >= ?", (token, datetime.now()))
        token_id = cursor.fetchone()[0]
        if token_id is None:
            flash("Geçersiz Bilgiler")
            return redirect(url_for("welcome"))
        cursor.execute("SELECT token FROM password_reset_requests WHERE id = ?", (token_id,))
        link_token = cursor.fetchone()[0]
        if link_token is None:
            flash("Geçersiz Bilgiler")
            return redirect(url_for("welcome"))
        return render_template("reset_password.html",token=link_token)

@app.route("/change_password", endpoint="change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        password = request.form.get("pass")
        confirmation = request.form.get("pass2")
        user_id = session["user_id"]

        if password == confirmation:
            if confirm_pass(password):
                hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
                cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user_id))
                conn.commit()
                flash("Şifreniz güncellenmiştir.")
                return redirect(url_for("change_password"))
            else:
                flash("Şifreniz geçersizdir.")
                return redirect(url_for("change_password"))
        else:
            flash("Şifreler uyuşmamaktadır.")
            return redirect(url_for("change_password"))
    
    else:
        return render_template("change_password.html")


@app.route("/logout", endpoint="logout", methods=["GET"])
def logout():
    session.clear()
    return redirect(url_for("welcome"))


@app.route("/register", endpoint="register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        if not username or not password or not confirmation:
            flash("Eksik bilgi")
            return redirect("/register")
        
        if not validate_email(email):
            flash("E-posta formatı yanlış")
            return redirect("/register")
        
        if len(password) < 8:
            flash("Şifre en az 8 karakter içermeli")
            return redirect("/register")
        
        if not (re.search(r'[a-z]', password) and re.search(r'[A-Z]', password)):
            flash("Şifre büyük harfler ve küçük harfler içermeli")
            return redirect("/register")
        
        if not re.search(r'\d', password):
            flash("Şifre en az bir rakam içermeli")
            return redirect("/register")
        
        if re.search(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/~`\\| ]', password):
            flash("Şifre özel karakter içermemeli")
            return redirect("/register")

        # Check if username already exists
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash("Kullanıcı adı alınmış. Lütfen başka bir isim deneyin.")
            return redirect(url_for("register"))

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        # Insert the new user into database
        cursor.execute("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", (username, email, hashed_password))
        conn.commit()

        flash("Kayıt başarılı")
        return redirect(url_for("dashboard"))

    else:
        return render_template("register.html")


@app.route("/dashboard", endpoint="dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    if request.method == "POST":
        product_name = request.form.get("product_name").lower()
        price = request.form.get("price")
        product_type = request.form.get("product_type").lower()
        purchase_date = request.form.get("date")
        user_id = session["user_id"]
        transaction_type = "bought"
        
        # Convert the date to ISO format
        date_object = datetime.strptime(purchase_date, '%d/%m/%Y')
        purchase_date = date_object.strftime('%Y-%m-%d')

        try:
            price = float(request.form.get("price"))
        except (ValueError, TypeError):
            flash("Geçersiz fiyat")
            return redirect(url_for("dashboard"))

        # Ensure that amount is valid
        try:    
            amount = int(request.form.get("amount"))
        except (ValueError, TypeError):
            flash("Adeti sayıyla belirtiniz")
            return redirect(url_for("dashboard"))

        # Ensure that "is_second_hand" value is valid
        try: 
            x = int(request.form.get("is_second_hand"))
        except (ValueError, TypeError):
            flash("1. el / 2. el seçiniz")
            return redirect(url_for("dashboard"))

        if amount <= 0:
            flash("Adet sıfırdan büyük olmalı")
            return redirect(url_for("dashboard"))

        is_second_hand_value = bool(x)

        # Prevent empty inputs from entering the database
        if not product_name or not product_type or is_second_hand_value is None or purchase_date is None or amount is None:
                flash("Ürün bilgisi eksik")
                return redirect(url_for("dashboard"))

        else:
            cursor.execute("SELECT category_name FROM category WHERE user_id = ?", (user_id,))
            names = cursor.fetchall()
            nameList = []

            if names:
                i = 0
                while i < len(names):
                    nameList.append(names[i][0])
                    i += 1

            total_price = price * amount

            # If there is such type of product
            if product_type in nameList:
                cursor.execute("SELECT id FROM category WHERE user_id = ? AND category_name = ?", (user_id, product_type))
                category_id = cursor.fetchone()[0]
                cursor.execute("INSERT INTO product (product_name, product_description, price, is_second_hand, category_id, user_id, purchase_date, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (product_name, product_type, price, is_second_hand_value, category_id, user_id, purchase_date, amount))
                cursor.execute("SELECT id FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                product_id = cursor.fetchone()[0]
                cursor.execute("INSERT INTO transaction_info (product_id, product_name, transaction_type, transaction_date, transaction_price, amount, total_price, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (product_id, product_name, transaction_type, purchase_date, price, amount, total_price, user_id))
                conn.commit()
                
                flash("Ürün eklediniz.")
                return redirect(url_for("dashboard"))

            # If there is not such type of product
            else:
                cursor.execute("INSERT INTO category (category_name, user_id) VALUES (?, ?)", (product_type, user_id))
                cursor.execute("SELECT id FROM category WHERE category_name = ? AND user_id = ?", (product_type, user_id))
                category_id = cursor.lastrowid
                cursor.execute("INSERT INTO product (product_name, product_description, price, is_second_hand, category_id, user_id, purchase_date, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (product_name, product_type, price, is_second_hand_value, category_id, user_id, purchase_date, amount))
                cursor.execute("SELECT id FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                product_id = cursor.fetchone()[0]
                cursor.execute("INSERT INTO transaction_info (product_id, product_name, transaction_type, transaction_date, transaction_price, amount, total_price, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (product_id, product_name, transaction_type, purchase_date, price, amount, total_price, user_id))
                conn.commit()

                flash("Ürün eklediniz.")
                return redirect(url_for("dashboard"))

    # If requested via GET
    else:
        user_id = session["user_id"]
        cursor.execute("SELECT product_name, product_description, price, is_second_hand, purchase_date, amount, id FROM product WHERE user_id = ? ORDER BY purchase_date ASC", (user_id,))
        productList = cursor.fetchall()
        keyList = ["name", "description", "price", "is_second_hand", "date", "amount", "id"]
        products = []

        for tuple in productList:
            productDict = dict.fromkeys(keyList, None)
            i = 0
            for key in productDict:
                productDict[key] = tuple[i]
                i += 1
            products.append(productDict)

        # Sort the products list
        products = sort(products)
        for product in products:
            product["date"] = format_date(product["date"])

        return render_template("dashboard.html", products=products)
    

@app.route("/sell", endpoint="sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        # Ensure that no invalid input enters the database
        product_name = request.form.get("product_name").lower()
        price = request.form.get("price")
        sold_date = request.form.get("date2")
        user_id = session["user_id"]
        transaction_type = "sold"

        # Convert date to ISO format
        try:
            date_object = datetime.strptime(sold_date, '%d/%m/%Y')
            sold_date = date_object.strftime('%Y-%m-%d')
        except ValueError:
            flash("Geçersiz bilgi")
            return redirect(url_for("sell"))

        try:
            price = float(request.form.get("price"))
        except (ValueError, TypeError):
            flash("Geçersiz bilgi")
            return redirect(url_for("sell"))

        # Ensure that amount is valid
        try:    
            amount = int(request.form.get("amount"))
        except (ValueError, TypeError):
            flash("Adeti sayıyla belirtiniz")
            return redirect(url_for("sell"))

        if amount <= 0:
            flash("Adet sıfırdan büyük olmalı")
            return redirect(url_for("sell"))

        checkList = [product_name, price, sold_date, amount]

        # Prevent empty inputs from entering the database
        for element in checkList:
            if element is None:
                flash("Ürün bilgisi eksik")
                return redirect(url_for("sell"))
            
        total_price = price * amount

        # Get the category id
        cursor.execute("SELECT category_id FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
        try:
            category_id = cursor.fetchone()[0]
        except TypeError:
            flash("Bu kategoride ürününüz yok")
            return redirect(url_for("sell"))

        cursor.execute("SELECT product_name FROM product WHERE user_id = ?", (user_id,))
        products = cursor.fetchall()
        cursor.execute("SELECT amount FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
        amount_in_db = cursor.fetchone()[0]
        cursor.execute("SELECT is_second_hand FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
        is_second_hand_value = cursor.fetchone()[0]

        # Check if the user has that product
        for product in products:
            if product_name == product[0]:
                if amount == amount_in_db:
                    cursor.execute("SELECT id FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                    product_id = cursor.fetchone()[0]
                    cursor.execute("SELECT product_description FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                    product_type = cursor.fetchone()[0]
                    cursor.execute(
                        "INSERT INTO sold_product (product_name, product_description, price, is_second_hand, category_id, user_id, sold_date, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (product_name, product_type, price, is_second_hand_value, category_id, user_id, sold_date, amount)
                        )
                    cursor.execute("INSERT INTO transaction_info (product_id, product_name, transaction_type, transaction_date, transaction_price, amount, total_price, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (product_id, product_name, transaction_type, sold_date, price, amount, total_price ,user_id))
                    cursor.execute("DELETE FROM product WHERE id = ?", (product_id,))
                    cursor.execute("SELECT product_name FROM product WHERE category_id = ?", (category_id,))
                    products_in_category = cursor.fetchall()

                    if not products_in_category:
                        cursor.execute("DELETE FROM category WHERE id = ?", (category_id,))
                        conn.commit()
                        flash("Ürün satıldı")
                        return redirect(url_for("sell"))
                    else:
                        conn.commit()
                        flash("Ürün satıldı")
                        return redirect(url_for("sell"))
                    
                elif amount > amount_in_db:
                    flash("Sahip olunandan fazla adet girildi")
                    return redirect(url_for("sell"))
                
                else:
                    new_amount = amount_in_db - amount
                    cursor.execute("SELECT id FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                    product_id = cursor.fetchone()[0]
                    cursor.execute("SELECT product_description FROM product WHERE product_name = ? AND user_id = ?", (product_name, user_id))
                    product_type = cursor.fetchone()[0]
                    cursor.execute("INSERT INTO sold_product (product_name, product_description, price, is_second_hand, category_id, user_id, sold_date, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (product_name, product_type, price, is_second_hand_value, category_id, user_id, sold_date, amount))
                    cursor.execute("INSERT INTO transaction_info (product_id, product_name, transaction_type, transaction_date, transaction_price, amount, total_price, user_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (product_id, product_name, transaction_type, sold_date, price, amount, total_price ,user_id))
                    cursor.execute("UPDATE product SET amount = ? WHERE product_name = ? AND user_id = ?", (new_amount, product_name, user_id))
                    conn.commit()
                    flash("Ürün satıldı")
                    return redirect(url_for("sell"))
            
        flash("Ürün elinizde yok")
        return redirect(url_for("sell"))
        
    else:
        return redirect(url_for("dashboard"))
        

@app.route("/history", endpoint="history", methods=["GET"])
@login_required
def history():
    if request.method == "GET":
        user_id = session["user_id"]
        cursor.execute("SELECT product_name, transaction_type, transaction_date, transaction_price, amount, total_price FROM transaction_info WHERE user_id = ?", (user_id,))
        transactions = cursor.fetchall()

        keyList = ["name", "type", "date", "price", "amount", "total_price"]
        transactionList = []

        for tuple in transactions:
            productDict = dict.fromkeys(keyList, None)
            i = 0
            for key in productDict:
                productDict[key] = tuple[i]
                i += 1
            transactionList.append(productDict)

        transactionList = sort(transactionList)
        for transaction in transactionList:
            transaction["date"] = format_date(transaction["date"])

        return render_template("history.html", transactionList=transactionList)

@app.route("/portfolio", endpoint="portfolio", methods=["GET", "POST"])
@login_required
def portfolio():
    if request.method == "GET":
        user_id = session["user_id"]
        cursor.execute("SELECT COUNT(*) FROM product WHERE user_id = ?",(user_id,))
        amount = cursor.fetchone()[0]
        cursor.execute("SELECT product_description, COUNT(*) FROM product WHERE user_id = ? GROUP BY product_description",(user_id,))
        data = cursor.fetchall()

        labels = [item[0] for item in data]
        sizes = [item[1] for item in data]


        # Create a pie chart
        plt.figure(figsize=(13, 13))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140, textprops={'fontsize': 25})
        plt.axis('equal')
        plt.tight_layout()

        # Save the pie chart as an image
        plt.savefig('static/pie_chart.png')

        global show_chart
        show_chart = False
        return render_template("portfolio.html", chart_data=None, show_chart=show_chart, amount=amount)

    else:
        user_id = session["user_id"]
        cursor.execute("SELECT COUNT(*) FROM product WHERE user_id = ?",(user_id,))
        amount = cursor.fetchone()[0]
        start_date = request.form.get("date1")
        end_date = request.form.get("date2")
        try:
            start_date = datetime.strptime(start_date, '%d/%m/%Y').strftime('%Y-%m-%d')
            end_date = datetime.strptime(end_date, '%d/%m/%Y').strftime('%Y-%m-%d')
        except ValueError:
            flash("Geçersiz Bilgi")
            return redirect(url_for("portfolio"))

        cursor.execute("SELECT transaction_date FROM transaction_info WHERE transaction_date >= ? AND transaction_date <= ? AND user_id = ?", (start_date, end_date, user_id))
        tDates = cursor.fetchall()
        dates_list = [date[0] for date in tDates]
        key_function = lambda x: datetime.strptime(x, '%Y-%m-%d')
        sorted_dates = sorted(dates_list, key=key_function)
        formatted_sorted_dates = [key_function(date).strftime('%d/%m/%Y') for date in sorted_dates]
        sumOfList = 0
        transactionList = []

        for date in formatted_sorted_dates:
            date = datetime.strptime(date, '%d/%m/%Y').strftime('%Y-%m-%d')
            cursor.execute("SELECT (CASE WHEN transaction_type == 'bought' THEN -total_price ELSE total_price END) FROM transaction_info WHERE transaction_date = ? AND user_id = ?", (date, user_id))
            current_price = int(cursor.fetchone()[0])

            # Update the cumulative sum with the current price
            sumOfList += current_price
            
            # Append the new cumulative sum to the list
            transactionList.append(sumOfList)

        # Create the line chart
        plt.figure(figsize=(10, 6))
        plt.plot(formatted_sorted_dates, transactionList, marker='o')
        plt.xlabel('Tarih')
        plt.ylabel('Net Para')
        start_date_display = datetime.strptime(start_date, '%Y-%m-%d').strftime('%d/%m/%Y')
        end_date_display = datetime.strptime(end_date, '%Y-%m-%d').strftime('%d/%m/%Y')
        plt.title('{} ve {} Arasındaki Kar-Zarar'.format(start_date_display, end_date_display))

        # Save the chart as an image
        image_stream = StringIO()
        plt.savefig(image_stream, format='svg')
        image_stream.seek(0)
        chart_data = image_stream.getvalue()
        image_stream.close()

        show_chart = True  # Set the flag to True
        return render_template("portfolio.html", chart_data=chart_data, show_chart=show_chart, amount=amount)

if __name__ == "__main__":
    app.run(debug=True)
