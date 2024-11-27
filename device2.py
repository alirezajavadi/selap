import ecdsa
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa import SECP256k1, SigningKey
import socket
import base64
import ascon as pyascon
import time
import random
import hashlib



# funs
def rand_num():
	return random.randint(1_000_000_000_000_000,9_000_000_000_000_000)

def from_b64(b64_str):
	return base64.b64decode(b64_str.encode('utf-8'))

def to_b64(bytes):
	return base64.b64encode(bytes).decode("ascii")


def derive_key(secret):
	_dk_byte = hashlib.pbkdf2_hmac('sha256', secret.encode(), "0".encode(), 10 ,16) # hash_name , secret, salt,
	return _dk_byte

def str_to_point(b64_str):
        point = Point.from_bytes(SECP256k1.curve, from_b64(b64_str))
        return PointJacobi(SECP256k1.curve, point.x(), point.y(),1)

# establishing the connection
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
host = '192.168.100.101'
port = 8910

try:
    sock.bind((host, port))
except socket.error as e:
    print(str(e))
    exit(0)

sock.listen()
device1, device1_address = sock.accept()


# init
curve = ecdsa.SECP256k1
G = curve.generator
v2 = 1234567890123456
Q2 = G * v2

v1 = 6543210987654321
Q1 = G * v1


# getting m1
m1 = device1.recv(10240).decode('utf-8')
print(f"\033[92m[ OK ] M1={{CT1, TG1, N1, T1}} has been received: {{{m1}}}\033[0m")

m1 = m1.split(',')

CT1_b64 = m1[0]
CT1_byte = from_b64(CT1_b64)
TG1_b64 = m1[1]
TG1_byte = from_b64(TG1_b64)
N1_b64 = m1[2]
N1 = str_to_point(N1_b64)
T1 = m1[3]

# m2
_t = v2 * N1
_K1_byte = derive_key(f"{_t.x()}{_t.y()}")
_K1_b64 = to_b64(_K1_byte)
additional_data = b"0" * 9
nonce = f"{N1.x()}"[:16].encode('utf-8')

decrypted_text = pyascon.ascon_decrypt(key=_K1_byte, nonce=nonce, associateddata=additional_data, ciphertext=CT1_byte + TG1_byte, variant="Ascon-AEAD128").decode('utf-8').split(',')

_en_T1 = decrypted_text[3]

if (time.time() - float(T1)) > 1000 or _en_T1 != T1:
	print("[ !! ] Invalid request.!")
	exit()

n2 = rand_num()
n2_q1 = n2 * Q1
K2_byte = derive_key(f"{n2_q1.x()}{n2_q1.y()}")
K2_b64 = to_b64(K2_byte)

N2 = n2 * G

_hin = f"{N1.x()}{N1.y()}{N2.x()}{N2.y()}{_K1_b64}{K2_b64}{T1}".encode('utf-8')
e2 = pyascon.ascon_hash(_hin)
e2_b64 = to_b64(e2)


ss2 = str( ((n2 + (int.from_bytes(e2, byteorder='big') *  v2)) % curve.order) )

nonce = f"{N2.y()}"[:16].encode('utf-8')
additional_data = b"0" * 9
T2 = time.time()
plaintext = f"{ss2},{to_b64(N2.to_bytes())},{T2}"
ciphertext = pyascon.ascon_encrypt(K2_byte, nonce, additional_data, plaintext.encode("utf-8"), variant="Ascon-AEAD128")
CT2_byte = ciphertext[:-16]
CT2_b64 = to_b64(CT2_byte)
TG2_byte = ciphertext[-16:]
TG2_b64 = to_b64(TG2_byte)

M2 = f"{CT2_b64},{TG2_b64},{to_b64(N2.to_bytes())}"
print(f"\033[96m[ <- ] Sending M2={{CT2, TG2, N2}} : {{{M2}}}\033[0m")
device1.send(M2.encode('utf-8'))

# getting m3
m3 = device1.recv(10240).decode('utf-8')
time.sleep(2)
print(f"\033[92m[ OK ] M3={{CT`1, TG`1}} has been received: {{{m3}}}\033[0m")
m3 = m3.split(',')
CT1_prime_b64 = m3[0]
CT1_prime_byte = from_b64(CT1_prime_b64)
TG1_prime_b64 = m3[1]
TG1_prime_byte = from_b64(TG1_prime_b64)

# final step
if (time.time() - T2 ) > 9000:
	print("[ !! ] Invalid request!")
	exit()

additional_data = b"0" * 9
nonce = f"{N1.y()}"[:16].encode('utf-8')

decrypted_text = pyascon.ascon_decrypt(_K1_byte, nonce, additional_data, CT1_prime_byte + TG1_prime_byte , variant="Ascon-AEAD128").decode('utf-8').split(',')
ss1 = decrypted_text[0]
N1_b64 = decrypted_text[1]

_check = (int(ss1) * G) + ( -1 * (int.from_bytes(e2, byteorder='big') * Q1) )
if N1 == _check:
	print("[ OK ] Device 1 has been authenticated successfully.")
_h = f"{e2_b64}{ss1}{ss2}"
SK12 = pyascon.ascon_hash(_h.encode('utf-8'))
SK12_b64 = to_b64(SK12)
device1.send("0".encode('utf-8')) # to calculate elapsed time
print(f"\033[1m[ OK ] Done! Session Key (SK): {SK12_b64}\033[0m")
