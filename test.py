import __ElGamal as ElGamal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import dsa, rsa

FILE_PATH = 'kljuc.pem'
import asn1
import base64



def generate_elgamal_pem_file(key_bytes, f, is_public = True):
    try:
        f.write(b'-----BEGIN ELGAMAL PUBLIC KEY-----\n' if is_public else b'-----BEGIN ELGAMAL PRIVATE KEY-----\n')
    
        # encoder = asn1.Encoder()
        # encoder.start()
        # encoder.write(int.from_bytes(key_bytes, "big"), asn1.Numbers.Integer)
        # encoded_bytes = encoder.output()
        toWrite = base64.b64encode(key_bytes)
        toWrite = str(toWrite)[2:-1]
        lines = list(map(''.join, zip(*[iter(toWrite)]*64)))
        for line in lines:
            f.write(bytes(line, 'utf-8'))
            f.write(b'\n')
        if len(toWrite[len(lines)*64 : ]) != 0:
            f.write(bytes(toWrite[len(lines)*64 : ] + '\n' , 'utf-8'))
        f.write(b'-----END ELGAMAL PUBLIC KEY-----' if is_public else b'-----END ELGAMAL PRIVATE KEY-----')
    except Exception as e:
        print(e)


def read_elgamal_pem_file(pem_file_path):
    f = open(pem_file_path, 'rb')
    lines = f.readlines()
    toDecode = ''
    is_public = lines[0]
    for line in lines[1:-1]:
        toDecode += str(line)[2:-2]
    toDecode = base64.b64decode(toDecode)
    size = 1024
    if is_public == b'-----BEGIN ELGAMAL PUBLIC KEY-----\n':
        print(len(lines[1:-1]))
        size = 1024 if len(lines[1:-1]) == 9 else 2048
        p = int.from_bytes(toDecode[0 : len(toDecode) // 3], byteorder='big')
        g = int.from_bytes(toDecode[len(toDecode) //3 : 2*len(toDecode) // 3], byteorder='big')
        y = int.from_bytes(toDecode[2*len(toDecode) //3 : len(toDecode)], byteorder='big')
        return (ElGamal.construct((p,g,y)), size)

    else:
        print(len(lines[1:-1]))
        size = 1024 if len(lines[1:-1]) == 11 else 2048
        p = int.from_bytes(toDecode[0 : len(toDecode) // 4], byteorder='big')
        g = int.from_bytes(toDecode[len(toDecode) // 4 : len(toDecode) // 2], byteorder='big')
        y = int.from_bytes(toDecode[len(toDecode) // 2 : 3 * len(toDecode) // 4], byteorder='big')
        x = int.from_bytes(toDecode[3 * len(toDecode) // 4 : len(toDecode)], byteorder='big')
        return (ElGamal.construct((p,g,y,x)), size)
    
k : ElGamal.ElGamalKey = ElGamal.generate(1024, randfunc=None)
message = b'gagasoni'


#text = k.decrypt(ciphertext=c)


private_key = k.p.to_bytes(byteorder='big') + k.g.to_bytes(byteorder='big') + k.y.to_bytes(byteorder='big') + k.x.to_bytes(byteorder='big')
public_key = k.p.to_bytes(byteorder='big') + k.g.to_bytes(byteorder='big') + k.y.to_bytes(byteorder='big')
f = open(FILE_PATH, 'wb+')
generate_elgamal_pem_file(private_key, f=f, is_public=False)
f.close()
k, size = read_elgamal_pem_file(FILE_PATH)






c = k.encrypt(plaintext=message, K=127)


# c1 = c[0].to_bytes(byteorder='big', length=c[0].bit_count()//8)
# c2 = c[1].to_bytes(byteorder='big', length=c[0].bit_count()//8)


s = len(str(c))
print(str(c))

text = k.decrypt(ciphertext=c)
print(text)






