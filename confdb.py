import sqlite3

# Criação do banco de dados 
def get_database():
    conn = sqlite3.connect('Banco_dados.db')
    conn.row_factory = sqlite3.Row
    return conn

# Criação da tabela 
def create_table():
    with get_database() as conn:
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gmail TEXT NOT NULL UNIQUE,
        password TEXT)""")
        conn.commit()
