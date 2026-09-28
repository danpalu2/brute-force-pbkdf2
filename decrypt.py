import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def decrypt(passwd):
    salt = b"\x.............."  # you should write here the salt obtained when encrypting
    cyphertext = b'..........'  # you should write here the cyphertext obtained when encrypting
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passwd))
    f = Fernet(key)
    try:
        print (f.decrypt(cyphertext))
        print ('right password: ' + str(passwd) + '\n')
    except:
        print ('wrong password: ' + str(passwd))
        pass

decrypt(b"TestPass")