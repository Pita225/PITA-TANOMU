"""PITA_タノムの短期管理者復旧トークンをローカルで生成する。"""

import getpass
import os
import re

from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash


ADMIN_RECOVERY_SALT = "pita-admin-recovery-v1"


def create_recovery_token(secret_key, login_id, password):
    """Generate a signed token without retaining the plaintext password."""
    serializer = URLSafeTimedSerializer(secret_key, salt=ADMIN_RECOVERY_SALT)
    return serializer.dumps({
        "purpose": "admin-recovery",
        "login_id": login_id,
        "password_hash": generate_password_hash(password),
    })


def main():
    secret_key = os.environ.get("SECRET_KEY") or getpass.getpass(
        "Renderに設定しているSECRET_KEY: "
    )
    if not secret_key:
        raise SystemExit("SECRET_KEYを正しく入力してください。")

    login_id = input("新しい管理者ログインID: ").strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,50}", login_id):
        raise SystemExit("ログインIDは半角英数字と . _ - を使い、3～50文字で入力してください。")

    password = getpass.getpass("新しい管理者パスワード（8文字以上）: ")
    confirmation = getpass.getpass("新しい管理者パスワード（確認）: ")
    if len(password) < 8:
        raise SystemExit("パスワードは8文字以上で入力してください。")
    if password != confirmation:
        raise SystemExit("確認用パスワードが一致しません。")

    token = create_recovery_token(secret_key, login_id, password)
    print("\n15分以内に /admin-recovery で次のトークンを使用してください。")
    print(token)


if __name__ == "__main__":
    main()
