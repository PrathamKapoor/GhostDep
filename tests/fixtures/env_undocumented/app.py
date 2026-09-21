import os

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.environ["JWT_SECRET"]


def connect():
    return DATABASE_URL
