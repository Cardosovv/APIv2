from confdb import get_database, create_table
from flask import request, jsonify, Flask
from hash import encode_pass, decode_pass
from autent import generate_token, valid_token

app = Flask(__name__)
    
#verificação porca de email
def validate_email(email):
    if '@' in email and '.' in email:
        return True
    return False


#tratamento de json e form
def get_request_data():
    if request.is_json:
        return request.get_json()
    elif request.form:
        return request.form
    else:
        return {}

#create database AND table
create_table()


# Criar conta 
@app.route('/register', methods=['POST'])
def register():

    data = get_request_data()
    gmail = data.get('gmail')
    password = data.get('password')
    
    if not validate_email(gmail):
        return jsonify({'Error':'Gmail is not validate'})

    if not gmail or not password:
        return jsonify({'Error': 'Gmail or Password not defined'}), 400

    with get_database() as conn:
        cur = conn.cursor()
        cur.execute("SELECT gmail FROM users WHERE gmail = ?", (gmail,))
        if cur.fetchone():
            return jsonify({'Error': 'Gmail is already registered'}), 409

        hashed_password = encode_pass(password)
        cur.execute("INSERT INTO users (gmail, password) VALUES (?, ?)", (gmail, hashed_password))
        conn.commit()

        cur.execute("SELECT id, gmail FROM users WHERE gmail =?", (gmail,))
        result = cur.fetchone()
        token = generate_token(result['id'], gmail)
        return jsonify({'Success': 'User registered successfully','token':token}), 201

# Login 
@app.route('/user/login', methods=['POST'])
def login():
    data = get_request_data()
    gmail = data.get('gmail')
    password = data.get('password')
    
    if not validate_email(gmail):
        return jsonify({'Error':'Gmail is not validate'})

    if not gmail or not password:
        return jsonify({'Error': 'Gmail or Password not defined'}), 400


    with get_database() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, password FROM users WHERE gmail = ?", (gmail,))
        user = cur.fetchone()

        if user and decode_pass(user['password'], password):
            token = generate_token(user['id'],gmail)
            return jsonify({'login': 'Success', 'token':token})
        return jsonify({'Error': 'Invalid credentials'}), 401

# Mostrar todos os usuários 
@app.route('/user', methods=['GET'])
def get_users():
    try:
        with get_database() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, gmail FROM users')
            rows = cur.fetchall()

            columns = [desc[0] for desc in cur.description]
            users = [dict(zip(columns, row)) for row in rows]
            return jsonify(users)
    except Exception as e:
        return jsonify({'Error': str(e)}), 500

# Mostrar um único usuário 
@app.route('/user/<int:id>', methods=['GET'])
def get_user_id(id):
    try:
        with get_database() as conn:
            cur = conn.cursor()
            cur.execute('SELECT id, gmail FROM users WHERE id = ?', (id,))
            user = cur.fetchone()            
            if user:
                return jsonify(dict(user))
            return jsonify({'Error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'Error': str(e)}), 500

# Deletar usuários
@app.route('/user/<int:id>', methods=['DELETE'])
def delete_user(id):
    with get_database() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id = ?', (id,))
        conn.commit()
        if cur.rowcount > 0:
            return jsonify({'Success': 'User deleted successfully'}), 200
        return jsonify({'Error': 'User not found'}), 404

# Atualizar usuário
@app.route('/user/<int:id>', methods=['PUT'])
def update_user(id):
    data = get_request_data()
    gmail = data.get('gmail')

    if not validate_email(gmail):
        return jsonify({'Error':'Gmail is not validate'})

    if not gmail:
        return jsonify({'Error': 'Gmail is required'}), 400 
    try:
        with get_database() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET gmail = ? WHERE id = ?', (gmail, id))
            conn.commit()
            if cur.rowcount > 0:
                return jsonify({'Success': 'Gmail updated successfully'}), 200
            return jsonify({'Error': 'User not found'}), 404
    except Exception as e:
        return jsonify({'Error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

