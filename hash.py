import bcrypt

#Encode password
def encode_pass(password):
    hased_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    return hased_password

#Decode password
def decode_pass(stored_passw, provided_pass):
    bcrypt.checkpw(provided_pass.encode('utf-8'), stored_passw.encode('utf-8'))
    return True


