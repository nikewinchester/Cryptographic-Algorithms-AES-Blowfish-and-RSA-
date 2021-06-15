import binascii
import random
import string
import Cryptodome.Util.number
from os import urandom
from Cryptodome.Cipher import AES
from Crypto.Cipher import Blowfish
import timeit
import time
from Crypto import Random
from struct import pack
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def generate_keys():
    modulus_length = 1024
    key = RSA.generate(modulus_length)
    pub_key = key.publickey()
    return key, pub_key

def encrypt_private_key(a_message, private_key):
    encryptor = PKCS1_OAEP.new(private_key)
    encrypted_msg = encryptor.encrypt(a_message)
    encoded_encrypted_msg = base64.b64encode(encrypted_msg)
    return encoded_encrypted_msg

def decrypt_public_key(encoded_encrypted_msg, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    decoded_encrypted_msg = base64.b64decode(encoded_encrypted_msg)
    decoded_decrypted_msg = encryptor.decrypt(decoded_encrypted_msg)
    return decoded_decrypted_msg

def RSA_Code(plaintext):

    private, public = generate_keys()
    message = plaintext

    encTime = 0;
    decTime = 0;
    a = 0;
    b = len(message)

    if(b>86):
        b = 85
    final = ""
    while True:
        if(a==b):
            break
        m_plain = message[a:b]
        m = bytes(m_plain,'utf-8')
        start_time = timeit.default_timer()
        encoded = encrypt_private_key(m, public)
        encTime = encTime + (timeit.default_timer() - start_time)

        start_time = timeit.default_timer()
        decoded = decrypt_public_key(encoded, private)
        decTime = decTime + (timeit.default_timer() - start_time)

        final = final + decoded.decode('utf-8')

        a = b
        b = a + 85
        if(b>len(message)):
            b = len(message)
    print("Encryption Time = ",encTime)
    print("Decryption Time = ",decTime)

    #print("final = ", final)

def AES_Code(result_str):
    key = b'fVS@Zu@zu6O0Mnas' #128 bit

    data = bytes(result_str,'utf-8')

    start_time = timeit.default_timer()
    e_cipher = AES.new(key, AES.MODE_EAX)
    e_data = e_cipher.encrypt(data)
    print("Encryption Time = ",(timeit.default_timer() - start_time)*1000)

    start_time = timeit.default_timer()
    d_cipher = AES.new(key, AES.MODE_EAX, e_cipher.nonce)
    d_data = d_cipher.decrypt(e_data)
    print("Decryption Time = ",(timeit.default_timer() - start_time)*1000)

    #print("final = ",d_data)


def Blowfish_Code(d):

    bs = Blowfish.block_size
    key = b'fVS@Zu@zu6O0Mnas' #128 bit
    iv = Random.new().read(bs)
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)

    plaintext = bytes(d,'utf-8')
    plen = bs - divmod(len(plaintext),bs)[1]
    padding = [plen]*plen
    padding = pack('b'*plen, *padding)
    plaintext = plaintext + padding
    start_time = timeit.default_timer()
    msg = iv + cipher.encrypt(plaintext)
    print("Encryption Time = ",(timeit.default_timer() - start_time)*1000)

    ciphertext =msg
    iv = ciphertext[:bs]
    ciphertext = ciphertext[bs:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    start_time = timeit.default_timer()
    msg = cipher.decrypt(ciphertext)
    print("Decryption Time = ",(timeit.default_timer() - start_time)*1000)
    last_byte = msg[-1]
    msg = msg[:- (last_byte if type(last_byte) is int else ord(last_byte))]


    #print("final = ",msg)




def Crypto_Code():

    #letters = string.ascii_lowercase
    #OriginalString = ''.join(random.choice(letters) for i in range(length))

    x = [1024,5120,10240,25600,51200,102400,256000,512000,768000,1048576,2097152,5242880,7864320,10485760]

    for i in x:
        OriginalString = "x" * i

        #print("Original = ",OriginalString)
        print("\n")
        print(i,"bytes\n")
        #print("RSA")
        #RSA_Code(OriginalString)
        print("AES")
        AES_Code(OriginalString)
        print("\n\nBlowfish")
        Blowfish_Code(OriginalString)

Crypto_Code()
