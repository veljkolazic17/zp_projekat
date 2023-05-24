from KeyRing import *
from Crypto.Hash import SHA1
from Crypto.Signature import DSS
from Crypto.Signature import pss
from Crypto.Cipher import CAST
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

    
    def sendMessage(self, message : bytes, filePath : str, pgpoptions : PGPOptions, privateKeyEntry : PrivateKeyRing.PrivateKeyRingEntry = None, password : str = None, publicKeyEntry : PublicKeyRing.PublicKeyRingEntry = None) -> bytes:
        
        messageToSend : bytes = message

        if pgpoptions.signature:

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
                messageToSend = signature + message
                
            elif privateKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
                rsaPrivateKey = RSA.importKey(extern_key=privateKey)

                # Signing
                signer = pss.new(rsaPrivateKey)
                signature = signer.sign(h)
                messageToSend = signature + message

        if pgpoptions.zip:
            messageToSend = gzip.compress(data=messageToSend,compresslevel=9)


        if pgpoptions.encryption:
            pass
        if pgpoptions.radix64:
            pass

        # Generate message
        return messageToSend