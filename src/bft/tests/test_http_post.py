import requests
import json
import hmac
import hashlib
import random
import string

def get_hmacsha256(key, message):
    key_bytes = bytes(key)
    message_bytes = bytes(message)
    hmacsha256_str = hmac.new(key_bytes, message_bytes, digestmod=hashlib.sha256).hexdigest()
    return hmacsha256_str


def random_str(count):
    seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+=-"
    sa = []
    for i in range(count):
        sa.append(random.choice(seed))
    salt = ''.join(sa)
    return salt

sha256_key = random_str(64)
message = random_str(1024)
gid = get_hmacsha256(sha256_key, message)
print(gid)

json_data = { 'data': {
        'gid': gid,
        'to':'ace6f33ae7b477f19c683d41374736cf8030f91d7bb5cc02d04ecc92e3a9b678',
        'amount': 1 }}

r = requests.post('http://3.81.161.170:8787/tx', data = json.dumps(json_data))
print(r)

