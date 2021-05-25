import base64
import json
import hmac
import hashlib

from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = "818eadc5afd48b2fbf45c56b93b8413a075f6fb3a367a457358290d6b8b69c47"
PASSWORD_SALT = "0ccfe2b669535c987b621241889be191f99509464346b1aed4bb049c65239ad5"

def sign_data(data: str) -> str:
    """Функция подписывает данные"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    """Вернет username если наша подпись совпала с куки, в противном случае None"""
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(usesrname: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[usesrname]['password'].lower()
    return password_hash == stored_password_hash

users = {
    "kirill@mail.ru": {
        "name": "Кирилл",
        "password": '107f8584b5d87a73bce2765a4c8804828340a475fd8ee98631986a876a9bd01f',
        "balance": 100_000
    },
    "petr@user.su": {
        "name": "Петя",
        "password": 'cd5bb88a553dec04fd40dd884ee3d134cd2b351454b70abf92c5d3144395a547',
        "balance": 500_000
    }
}


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(
        f"Привет, {users[valid_username]['name']}! <br/>"
        f"Баланс: {users[valid_username]['balance']}",
        media_type='text/html')


@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data['username']
    password = data['password']
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": 'Я Вас не знаю',
            }), 
            media_type='application/json')
    
    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет, {user['name']}! <br/> Ваш баланс: {user['balance']}"
        }),
        media_type='application/json')

    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response
