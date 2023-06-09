from KeyRing import *
from Crypto.Hash import SHA1
from Crypto.Signature import DSS
from Crypto.PublicKey import DSA
from Crypto.Signature import pss
from Crypto.Cipher import CAST
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
import base64

# from Crypto.Cipher import PKCS1_v1_5
from Crypto.Cipher import PKCS1_OAEP

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

    def checkPGPOptions(self, filePath : str) -> PGPOptions:
        f = open(filePath, 'rb')
        pgpOptionsBytes = list(f.read(4))
        pgpOptions : PGPOptions = PGPOptions()
        pgpOptions.signature = True if int(pgpOptionsBytes[0]) - 48 == 1 else False
        pgpOptions.zip = True if int(pgpOptionsBytes[1]) - 48 == 1 else False
        pgpOptions.encryption = True if int(pgpOptionsBytes[2]) - 48 == 1 else False
        pgpOptions.radix64 = True if int(pgpOptionsBytes[3]) - 48 == 1 else False
        return pgpOptions
        
        pgpOptions
    def sendMessage(self, message : bytes, filePath : str, pgpoptions : PGPOptions, algotTypeSym : AlgoTypeSym = None, privateKeyEntry : PrivateKeyRing.PrivateKeyRingEntry = None, password : str = None, publicKeyEntry : PublicKeyRing.PublicKeyRingEntry = None) -> bytes:

        f = open(filePath, 'wb')

        
        for i in [pgpoptions.signature, pgpoptions.zip, pgpoptions.encryption, pgpoptions.radix64]:
            f.write('1'.encode('utf-8') if i else '0'.encode('utf-8'))

        if publicKeyEntry:
            if publicKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
                f.write('1'.encode('utf-8'))
            elif publicKeyEntry.algoTypeAsym == AlgoTypeAsym.DSA:
                f.write('2'.encode('utf-8'))
            elif publicKeyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
                f.write('3'.encode('utf-8'))
        else:
            f.write('0'.encode('utf-8'))

        if privateKeyEntry:
            if privateKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
                f.write('1'.encode('utf-8'))
            elif privateKeyEntry.algoTypeAsym == AlgoTypeAsym.DSA:
                f.write('2'.encode('utf-8'))
            elif publicKeyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
                f.write('3'.encode('utf-8'))
        else:
            f.write('0'.encode('utf-8'))

        if algotTypeSym == AlgoTypeSym.CAST5:
            f.write('1'.encode('utf-8'))
        elif algotTypeSym == AlgoTypeSym.AES128:
            f.write('2'.encode('utf-8'))
        else:
            f.write('0'.encode('utf-8'))

        if privateKeyEntry:
            if privateKeyEntry.keySizeAsym == KeySizeAsym.KEY1024:
                f.write('1'.encode('utf-8'))
            elif privateKeyEntry.keySizeAsym == KeySizeAsym.KEY2048:
                f.write('2'.encode('utf-8'))
        else:
            f.write('0'.encode('utf-8'))

        if publicKeyEntry:            
            if publicKeyEntry.keySizeAsym == KeySizeAsym.KEY1024:
                f.write('1'.encode('utf-8'))
            elif publicKeyEntry.keySizeAsym == KeySizeAsym.KEY2048:
                f.write('2'.encode('utf-8'))
        else:
            f.write('0'.encode('utf-8'))

        messageToSend : bytes = message

        # Sign the message
        if pgpoptions.signature and privateKeyEntry:

            # Hash password
            h = SHA1.new()
            h.update(bytes(password, 'utf-8'))
            hashed_password = h.digest()
            hashed_password = hashed_password[0:16]

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
        if pgpoptions.encryption and publicKeyEntry:

            sessionKey : bytes = get_random_bytes(16)
            publicKey : bytes = publicKeyEntry.publicKey

            if algotTypeSym == AlgoTypeSym.CAST5:
                messageToSend = CAST.new(sessionKey, CAST.MODE_OPENPGP).encrypt(messageToSend)
            elif algotTypeSym == AlgoTypeSym.AES128:
                messageToSend = AES.new(sessionKey, AES.MODE_OPENPGP, iv=b'0123456789abcdef').encrypt(messageToSend)

            if publicKeyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
                try:
                    p = int.from_bytes(publicKey[0 : len(publicKey) // 3], byteorder='big')
                    g = int.from_bytes(publicKey[len(publicKey) //3 : 2*len(publicKey) // 3], byteorder='big')
                    y = int.from_bytes(publicKey[2*len(publicKey) //3 : len(publicKey)], byteorder='big')
                    elgamalPublicKey = ElGamal.construct((p,g,y))
                    sessionKey = bytes(str(elgamalPublicKey.encrypt(plaintext=sessionKey, K = 127)),'utf-8')
                except Exception as e:
                    print(e)
            elif publicKeyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
                rsaPublicKey = RSA.importKey(extern_key=publicKey)
                sessionKey = PKCS1_OAEP.new(rsaPublicKey).encrypt(sessionKey)

            messageToSend = publicKeyEntry.keyID + b'\n' + sessionKey + b'\n' + messageToSend


        if pgpoptions.radix64:
            messageToSend = base64.b64encode(messageToSend)

        f.write(messageToSend)
        f.close()

        # Generate message
        return messageToSend
    

    def receiveMessage(self, filePath : str, password : str):
        f = open(filePath, 'rb')

        email = ""
        messageToReceive = list(f.read())
        f.close() 
        pgpoptions : PGPOptions = PGPOptions()
        pgpoptions.signature = bool(int(messageToReceive[0] - 48))
        pgpoptions.zip = bool(int(messageToReceive[1] - 48))
        pgpoptions.encryption = bool(int(messageToReceive[2] - 48))
        pgpoptions.radix64 = bool(int(messageToReceive[3] - 48))

        encryptionTypeAsym : AlgoTypeAsym = AlgoTypeAsym(int(messageToReceive[4] - 48))
        signatureTypeAsym : AlgoTypeAsym = AlgoTypeAsym(int(messageToReceive[5] - 48))
        encryptionTypeSym : AlgoTypeSym = AlgoTypeSym(int(messageToReceive[6] - 48))
        keySizeSignature : KeySizeAsym = KeySizeAsym(int(messageToReceive[7] - 48)*1024)
        keySizeEncryption : KeySizeAsym = KeySizeAsym(int(messageToReceive[8] - 48)*1024)


        messageToReceive = bytes(messageToReceive[9:])
          
        if pgpoptions.radix64:
            messageToReceive = base64.b64decode(messageToReceive)

        if pgpoptions.encryption:
            messageToReceive = messageToReceive.split(b'\n')
            keyID = messageToReceive[0]
            sessionKey = messageToReceive[1]
            messageToReceive = messageToReceive[2]

            privateKeyEntry : PrivateKeyRing.PrivateKeyRingEntry = self.privateKeyRing.findEntryByKeyID(keyID=keyID)

            if privateKeyEntry == None:
                # Mozda neka poruka
                raise ValueError("PRIVATE KEY NOT FOUND!")
                

            h = SHA1.new()
            h.update(bytes(password, 'utf-8'))
            hashed_password = h.digest()
            hashed_password = hashed_password[0:16]

            # Decrypted key
            eiv = privateKeyEntry.encrtyptedPrivateKey[:CAST.block_size+2]
            ciphertext = privateKeyEntry.encrtyptedPrivateKey[CAST.block_size+2:]
            cipher = CAST.new(hashed_password, CAST.MODE_OPENPGP, eiv)
            privateKey = cipher.decrypt(ciphertext)
            try:
                if encryptionTypeAsym == AlgoTypeAsym.ELGAMAL:
                    try:
                        print(sessionKey)
                        sessionKey = sessionKey.decode('utf-8')
                        ints = sessionKey[1:-1].split(',')
                        sessionKey = [int(ints[0]), int(ints[1])]
                        print(sessionKey)
                        p = int.from_bytes(privateKey[0 : len(privateKey) // 4], byteorder='big')
                        g = int.from_bytes(privateKey[len(privateKey) // 4 : len(privateKey) // 2], byteorder='big')
                        y = int.from_bytes(privateKey[len(privateKey) // 2 : 3 * len(privateKey) // 4], byteorder='big')
                        x = int.from_bytes(privateKey[3 * len(privateKey) // 4 : len(privateKey)], byteorder='big')
                        elgamalPrivateKey =  ElGamal.construct((p,g,y,x))
                        sessionKey = elgamalPrivateKey.decrypt(sessionKey)
                    except Exception as e:
                        print(e)
                elif encryptionTypeAsym == AlgoTypeAsym.RSA:
                    rsaPrivateKey = RSA.import_key(extern_key=privateKey)
                    sessionKey = PKCS1_OAEP.new(rsaPrivateKey).decrypt(sessionKey)
                if encryptionTypeSym == AlgoTypeSym.CAST5:
                    eiv = messageToReceive[:CAST.block_size+2]
                    ciphertext = messageToReceive[CAST.block_size+2:]
                    cipher = CAST.new(sessionKey, CAST.MODE_OPENPGP, eiv)
                    messageToReceive = cipher.decrypt(ciphertext)
                elif encryptionTypeSym == AlgoTypeSym.AES128:
                    iv = messageToReceive[:AES.block_size+2]
                    ciphertext = messageToReceive[AES.block_size+2:]
                    messageToReceive = AES.new(sessionKey, AES.MODE_OPENPGP, iv=iv).decrypt(ciphertext)
            except:
                raise ValueError("WRONG PASSWORD!")

        # Unzip the message
        if pgpoptions.zip:
            messageToReceive = gzip.decompress(data=messageToReceive)

        # Signature check
        if pgpoptions.signature:
            keyID : bytes = messageToReceive[0:8]
            digest : bytes = None 
            try:
                publicKeySignature : PublicKeyRing.PublicKeyRingEntry = self.publicKeyRing.findEntryByKeyID(keyID=keyID).publicKey
                email = self.publicKeyRing.findEntryByKeyID(keyID=keyID).userID
            except:
                raise ValueError("PUBLIC KEY NOT FOUND!")

            if signatureTypeAsym == AlgoTypeAsym.DSA:
                if keySizeSignature == KeySizeAsym.KEY1024:
                    digest = messageToReceive[8:48]
                    messageToReceive = messageToReceive[48:]
                elif keySizeSignature == KeySizeAsym.KEY2048:
                    digest = messageToReceive[8:64]
                    messageToReceive = messageToReceive[64:]

                key = DSA.import_key(extern_key=publicKeySignature)
                h = SHA1.new(messageToReceive)
                verifier = DSS.new(key, 'fips-186-3')
                try:
                    verifier.verify(h, digest)
                    #print("The message is authentic")
                except:
                    raise ValueError("THE MESSAGE IS NOT AUTHENTIC!")

            elif signatureTypeAsym == AlgoTypeAsym.RSA:
                if keySizeSignature == KeySizeAsym.KEY1024:
                    digest = messageToReceive[8:136]
                    messageToReceive = messageToReceive[136:]
                elif keySizeSignature == KeySizeAsym.KEY2048:
                    digest = messageToReceive[8:264]
                    messageToReceive = messageToReceive[264:]
                key = RSA.import_key(extern_key=publicKeySignature)
                h = SHA1.new(messageToReceive)
                verifier = pss.new(key)
                try:
                    verifier.verify(h, digest)
                    print("The message is authentic")
                except:
                    raise ValueError("THE MESSAGE IS NOT AUTHENTIC!")



        return messageToReceive,email