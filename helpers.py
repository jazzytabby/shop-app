from flask import redirect, session, flash
from datetime import datetime
from functools import wraps
import re

def login_required(f):
    # This function is from CS50's source code for Week 9 PSET. There's no need to reinvent the wheel.
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)

    return decorated_function


def tl(value):
    """Format value as TRY (Turkish Lira)."""
    return f"₺{value:,.2f}"


def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None


def compare_date(date_str1, date_str2):
    date1 = datetime.strptime(date_str1, '%Y-%m-%d')
    date2 = datetime.strptime(date_str2, '%Y-%m-%d')

    if date1 < date2:
        return True
    return False

def format_date(date_str):
    # Convert the date in ISO format to a datetime object
    date_object = datetime.strptime(date_str, '%Y-%m-%d')

    # Format the datetime object as DD/MM/YYYY with slashes
    formatted_date = date_object.strftime('%d/%m/%Y')
    return formatted_date


def sort(products):
    return sorted(products, key=lambda x: datetime.strptime(x['date'], '%Y-%m-%d'), reverse=True)


def confirm_pass(password):
    if len(password) < 8:
        flash("Şifre en az 8 karakter içermeli")
        return False

    elif not (re.search(r'[a-z]', password) and re.search(r'[A-Z]', password)):
        flash("Şifre büyük harfler ve küçük harfler içermeli")
        return False
    
    elif not re.search(r'\d', password):
        flash("Şifre en az bir rakam içermeli")
        return False
    
    elif re.search(r'[!@#$%^&*()_+{}\[\]:;"\'<>,.?/~`\\| ]', password):
        flash("Şifre özel karakter içermemeli")
        return False
    
    else:
        return True