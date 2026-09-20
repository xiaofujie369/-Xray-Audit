"""Generate a private first-install configuration without exposing secrets in argv."""

import getpass
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit


def main():
    destination = Path(__file__).parent / ".env"
    if destination.exists():
        raise SystemExit(
            ".env already exists; edit it directly. Existing database credentials are preserved."
        )
    public = input("中央 HTTPS 地址，例如 https://audit.example.com: ").strip().rstrip("/")
    parsed = urlsplit(public)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("Use an HTTPS origin without path, query or embedded credentials.")
    email = input("初始管理员邮箱: ").strip()
    if "@" not in email or any(c in email for c in "\r\n# \t"):
        raise SystemExit("Invalid administrator email")
    password = getpass.getpass("管理员密码（至少 14 字符）: ")
    if len(password) < 14 or len(password) > 256 or any(c in password for c in "\r\n'"):
        raise SystemExit("Use 14-256 characters without newlines or a single quote.")
    if password != getpass.getpass("再次输入密码: "):
        raise SystemExit("Passwords do not match")
    database_password = secrets.token_hex(32)
    values = {
        "APP_ENV": "production",
        "APP_SECRET": secrets.token_hex(32),
        "ADMIN_EMAIL": email,
        "ADMIN_PASSWORD": password,
        "POSTGRES_PASSWORD": database_password,
        "DATABASE_URL": f"postgresql+psycopg://audit:{database_password}@postgres:5432/audit",
        "REDIS_URL": "redis://redis:6379/0",
        "PUBLIC_URL": public,
        "TELEGRAM_ENABLED": "false",
        "WEBHOOK_ENABLED": "false",
    }
    fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        # Compose single-quoted values preserve $, #, spaces and backslashes.
        output.write("".join(f"{key}='{value}'\n" for key, value in values.items()))
    print("Private .env created. Run: bash audit-server/install-central.sh --https")


if __name__ == "__main__":
    main()
