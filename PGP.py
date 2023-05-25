from KeyRing import *
from Crypto.Hash import SHA1
from Crypto.Signature import DSS
from Crypto.Signature import pss
from Crypto.Cipher import CAST
from Crypto.Cipher import AES

from Crypto.Cipher import PKCS1_v1_5

from Crypto.Random import get_random_bytes


import gzip

class PGPOptions:
    signature : bool
    zip : bool
    encryption : bool
    radix64 : bool

    def __init__(self, signature : bool = False, zip : bool = False, encryption : bool = False, radix64 : bool = False) -> None:
        self.signature = signature
        self.zip = zip
        self.encryption = encryption
        self.radix64 = radix64

class PGP:
    publicKeyRing : PublicKeyRing
    privateKeyRing : PrivateKeyRing


    def __init__(self) -> None:
        self.publicKeyRing = PublicKeyRing()
        self.privateKeyRing = PrivateKeyRing()

    
    def sendMessage(self, message : bytes, filePath : str, pgpoptions : PGPOptions, algotTypeSym : AlgoTypeSym = None, privateKeyEntry : PrivateKeyRing.PrivateKeyRingEntry = None, password : str = None, publicKeyEntry : PublicKeyRing.PublicKeyRingEntry = None) -> bytes:
        
        messageToSend : bytes = message

        # Sign the message
        if pgpoptions.signature and privateKeyEntry:

            # Hash password
            h = SHA1.new()
            h.update(bytes(password, 'utf-8'))
            hashed_password = h.digest()
            hashed_password = hashed_password[0:15]

            # Decrypted key
            eiv = privateKeyEntry.encrtyptedPrivateKey[:CAST.block_size+2]
            ciphertext = privateKeyEntry.encrtyptedPrivateKey[CAST.block_size+2:]
            cipher = CAST.new(hashed_password, CAST.MODE_OPENPGP, eiv)
            privateKey = cipher.decrypt(ciphertext)

            # Hash message
            h = SHA1.new(message)

            if privateKeyEntry.algoTypeAsym == AlgoTypeAsym.DSA:
                dsaPrivateKey = DSA.importKey(extern_key=privateKey)

                # Signing
                signer = DSS.new(dsaPrivateKey, 'fips-186-3')
                signature = signer.sign(h)
                
            elif privateKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
                rsaPrivateKey = RSA.importKey(extern_key=privateKey)

                # Signing
                signer = pss.new(rsaPrivateKey)
                signature = signer.sign(h)
            
            messageToSend = privateKeyEntry.keyID + signature + message

        # Zip the message
        if pgpoptions.zip:
            messageToSend = gzip.compress(data=messageToSend,compresslevel=9)

        # Encrypt the message
        if pgpoptions.encryption:

            sessionKey : bytes = get_random_bytes(16)
            publicKey : bytes = publicKeyEntry.publicKey

            if algotTypeSym == AlgoTypeSym.CAST5:
                messageToSend = CAST.new(sessionKey, CAST.MODE_OPENPGP).encrypt(messageToSend)
            elif algotTypeSym == AlgoTypeSym.AES128:
                messageToSend = AES.new(sessionKey, AES.MODE_OPENPGP, iv=b'0123456789abcdef').encrypt(messageToSend)

            if publicKeyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
                pass
            elif publicKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:

                rsaPublicKey = RSA.importKey(extern_key=publicKey)
                sessionKey = PKCS1_v1_5.new(rsaPublicKey).encrypt(sessionKey)

            messageToSend = publicKeyEntry.keyID + sessionKey + messageToSend


        if pgpoptions.radix64:
            pass

        # Generate message
        return messageToSend