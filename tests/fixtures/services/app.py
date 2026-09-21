import psycopg2

DATABASE_URL = "postgresql://user:pass@localhost:5432/app"
CACHE_URL = "redis://localhost:6379/0"


def get_conn():
    return psycopg2.connect(DATABASE_URL)
