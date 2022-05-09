# import argparse
#
#
# def validator(value: int):
#     if not isinstance(value, int):
#         raise argparse.ArgumentError
#     return value**2
#
#
# parser = argparse.ArgumentParser()
# parser.add_argument('-u', '--user', help='user to app')
# parser.add_argument('-p', '--password', help='password to app')
# parser.add_argument('-m', '--mode', help='mode to app', choices=['encrypt', 'decrypt'])
# parser.add_argument('-v', '--verbose', help='verbose to app', action='count', default=0)
# parser.add_argument('-sq', '--square', help='square of number', type=int)
# parser.add_argument('-su', '--sum', help='square of number', type=int, action='append')
#
# args = parser.parse_args()
#
# print(args)


import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

password = b'qwe'
SALT = b'.z0.W3*JSONV'
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=390000
)
kdf2 = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=390000
)

pass_1 = base64.urlsafe_b64encode(kdf.derive(password))
pass_2 = base64.urlsafe_b64encode(kdf.derive(password))

# if pass_2 == pass_1:
#     print('weszło')
