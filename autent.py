from jose import jwt
import datetime
from config import Config

def generate_token(user_id,gmail):
    now = datetime.datetime.utcnow()
    data = {
        "sub": user_id,
        "gmail": gmail,
        "exp": now + datetime.timedelta(hours=1)
    }
    token = jwt.encode(data, Config.SECRET_KEY, algorithm=Config.ALGORITHM)
    return token

def valid_token(token):
    try:
        valid = jwt.decode(token, Config.SECRET_KEY, algorithms=[Config.ALGORITHM])
        if valid:
            return jsonify({"Success":"Token is okay"})
    except jwt.ExpiredSignatureError as e:
        return jsonify ({"Error":"Token expired"})
    except Exception as e:
        return jsonify({"Error": str(e)})
