import time
import ascon as pyascon
import random
import hashlib
import base64
import ecdsa
from ecdsa.ellipticcurve import Point, PointJacobi
from ecdsa import SECP256k1, SigningKey
import socket

start = time.time() # measuring time

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
        point = Point.from_bytes(SECP256k1.curve, base64.b64decode(b64_str.encode('utf-8')))
        return PointJacobi(SECP256k1.curve, point.x(), point.y(),1)


# establishing the connection
HOST = "192.168.100.101" # Device2 IP address
PORT = 8910
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

# init
curve = ecdsa.SECP256k1
G = curve.generator
v2 = 1234567890123456
Q2 = G * v2

v1 = 6543210987654321
Q1 = G * v1

# m1
n1 = rand_num()
n1_q2 = n1 * Q2
K1_byte = derive_key(f"{n1_q2.x()}{n1_q2.y()}")
K1_b64 = to_b64(K1_byte)


N1 = n1 * G
N1_b64 = to_b64(N1.to_bytes())
_temp = 11223344556677889900
R1 ,s1 = _temp * G , _temp

T1 = time.time()

Q1_b64 = base64.b64encode(Q1.to_bytes()).decode('utf-8')
R1_b64 = base64.b64encode(R1.to_bytes()).decode('utf-8')
_plain_text = f"{Q1_b64},{R1_b64},{s1},{T1}".encode('utf-8')
additional_data = b"0" * 9
nonce = f"{N1.x()}"[:16].encode('utf-8')

ciphertext = pyascon.ascon_encrypt(key=K1_byte, nonce=nonce, associateddata=additional_data, plaintext=_plain_text, variant="Ascon-AEAD128")
CT1 = to_b64(ciphertext[:-16])
TG1 = to_b64(ciphertext[-16:])

M1 = f"{CT1},{TG1},{N1_b64},{T1}"
print(f"\033[96m[ -> ] Sending M1={{CT1, TG1, N1, T1}} : {{{M1}}}\033[0m")
sock.send(M1.encode('utf-8'))

# getting m2
m2 = sock.recv(10240).decode('utf-8')
print(f"\033[92m[ OK ] M2={{CT2, TG2, N2}} has been received: {{{m2}}}\033[0m")

m2 = m2.split(',')
CT2_b64 = m2[0]
CT2_byte = from_b64(CT2_b64)
TG2_b64 = m2[1]
TG2_byte = from_b64(TG2_b64)
N2_b64 = m2[2]
N2 = str_to_point(N2_b64)


# m3
if (time.time() - T1) > 9000 : # check arrival time
	print(f"[ !! ] Invalid request!")
	exit()

_t = v1 * N2
_K2_byte = derive_key(f"{_t.x()}{_t.y()}")
_K2_b64 = to_b64(_K2_byte)
additional_data = b"0" * 9
nonce = f"{N2.y()}"[:16].encode('utf-8')

decrypted_text = pyascon.ascon_decrypt(_K2_byte, nonce, additional_data, CT2_byte + TG2_byte , variant="Ascon-AEAD128").decode('utf-8').split(',')
de_ss2 = decrypted_text[0]
de_N2_b64 = decrypted_text[1]
de_T2 = decrypted_text[2]

if (time.time() -float(de_T2)) > 9000:
	print(f"[ !! ] Invalid request!")
	exit()

_h_in = f"{N1.x()}{N1.y()}{N2.x()}{N2.y()}{K1_b64}{_K2_b64}{T1}".encode('utf-8')
e2_prime = pyascon.ascon_hash(_h_in)
e2_prime_b64 = to_b64(e2_prime)

_check = (int(de_ss2) * G) + (-1 * (int.from_bytes(e2_prime, byteorder='big') * Q2) )

if _check == N2 :
	print("[ OK ] Device 2 has been  authenticated successfully.")

ss1 = str( ((n1 + (int.from_bytes(e2_prime, byteorder='big') *  v1)) % curve.order) )

_h = f"{e2_prime_b64}{ss1}{de_ss2}"
SK12 = pyascon.ascon_hash(_h.encode('utf-8'))
SK12_b64 = to_b64(SK12)

additional_data = b"0" * 9
nonce = f"{N1.y()}"[:16].encode('utf-8')
plain_text = f"{ss1},{N1_b64}".encode('utf-8')
decrypted_text = pyascon.ascon_encrypt(K1_byte, nonce, additional_data, plain_text , variant="Ascon-AEAD128")
CT1_prime = decrypted_text[:-16]
TG1_prime = decrypted_text[-16:]

M3 = f"{to_b64(CT1_prime)},{to_b64(TG1_prime)}"
print(f"\033[96m[ -> ] Sending M3={{CT`1, TG`1}} : {{{M3}}}\033[0m")
print(f"\033[1m[ OK ] Done! Session Key (SK): {SK12_b64}\033[0m")
sock.send(M3.encode('utf-8'))

# time
sock.recv(10)
elps = (time.time() - T1) * 1000

print(f"--------------\nElapsed Time: {elps}")

with open("timing.txt" , "a") as f:
	f.write(f"{elps}\n")
