import os
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
import jwt
from flask import Flask, request, jsonify, g
from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


app = Flask(__name__)

# chave
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError("Configure a variavel JWT_SECRET_KEY")

DATABASE = "users.db"
JWT_ALGORITHM = "HS256"
TOKEN_EXPIRATION = 30

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row

    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.commit()
    db.close()


# ----------------------------------------
# Geração de JWT
# ----------------------------------------

def generate_token(user_id):
    payload = {
        "sub": str(user_id),
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc)
              + timedelta(minutes=TOKEN_EXPIRATION)
    }

    token = jwt.encode(
        payload,
        SECRET_KEY,
        algorithm=JWT_ALGORITHM
    )

    return token


# ----------------------------------------
# Decorator de autenticação
# ----------------------------------------

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return jsonify({
                "error": "Token de autenticação ausente"
            }), 401

        parts = auth_header.split()

        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({
                "error": "Formato de autenticação inválido"
            }), 401

        token = parts[1]

        try:
            payload = jwt.decode(
                token,
                SECRET_KEY,
                algorithms=[JWT_ALGORITHM]
            )

            user_id = int(payload["sub"])

        except (jwt.InvalidTokenError, ValueError, KeyError):
            return jsonify({
                "error": "Token inválido ou expirado"
            }), 401

        db = get_db()

        user = db.execute(
            "SELECT id, username FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()

        if user is None:
            return jsonify({
                "error": "Usuário não encontrado"
            }), 401

        g.current_user = user

        return f(*args, **kwargs)

    return decorated


# ----------------------------------------
# Cadastro
# ----------------------------------------

@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Envie um JSON válido"
        }), 400

    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "error": "Username e password devem ser strings"
        }), 400

    if len(username) < 3 or len(username) > 50:
        return jsonify({
            "error": "Username deve ter entre 3 e 50 caracteres"
        }), 400

    if len(password) < 12:
        return jsonify({
            "error": "Senha deve ter pelo menos 12 caracteres"
        }), 400

    password_hash = generate_password_hash(password)

    db = get_db()

    try:
        db.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        db.commit()

    except sqlite3.IntegrityError:
        return jsonify({
            "error": "Username já cadastrado"
        }), 409

    return jsonify({
        "message": "Usuário cadastrado com sucesso"
    }), 201


# ----------------------------------------
# Login
# ----------------------------------------

@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json(silent=True)

    if not data:
        return jsonify({
            "error": "Envie um JSON válido"
        }), 400

    username = data.get("username", "")
    password = data.get("password", "")

    if not isinstance(username, str) or not isinstance(password, str):
        return jsonify({
            "error": "Credenciais inválidas"
        }), 400

    db = get_db()

    user = db.execute(
        """
        SELECT id, username, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    if user is None or not check_password_hash(
        user["password_hash"], password
    ):
        return jsonify({
            "error": "Username ou senha incorretos"
        }), 401

    token = generate_token(user["id"])

    return jsonify({
        "message": "Login realizado com sucesso",
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": TOKEN_EXPIRATION * 60
    }), 200


# ----------------------------------------
# Endpoint protegido
# ----------------------------------------

@app.route("/api/me", methods=["GET"])
@token_required
def me():

    user = g.current_user

    return jsonify({
        "id": user["id"],
        "username": user["username"]
    }), 200


# ----------------------------------------
# Inicialização
# ----------------------------------------

if __name__ == "__main__":
    init_db()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
