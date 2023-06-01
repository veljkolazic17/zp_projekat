import datetime

from User import *

from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import CAST
from Crypto.Hash import SHA1
from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key


class KeyRing:
    def __init__(self) -> None:
        self.keyMap = {}
        self.size = 0
    def findEntryByKeyID(self, keyID : bytes):
        for _, value in self.keyMap.items():
            for entry in value:
                if entry.keyID == keyID:
                    return entry
        return None
    def __str__(self) -> str:
        res : str = ""
        for key in self.keyMap.keys():
            for entry in self.keyMap[key]:
                res += entry.userID + " " + str(entry.keyID)
            res += '\n'
        return res
    
    def deleteEntryByKeyID(self, keyID : bytes):
        for _, value in self.keyMap.items():
            for entry in value:
                if entry.keyID == keyID:
                    value.remove(entry)
                    self.size -= 1
                    return True
        return False
    def deleteEntryByUserID(self, userID : str):
        for key,_ in self.keyMap.items():
            if key == userID:
                self.size -= 1
                del self.keyMap[key]
                return True
        return False
    def exportPublicKey(self, filePath : str ,keyID: bytes):
        f = open(file=filePath, mode='wb+')
        keyEntry = self.findEntryByKeyID(keyID=keyID)
        if keyEntry.algoTypeAsym == AlgoTypeAsym.DSA:
            dsaKey = DSA.import_key(extern_key=keyEntry.publicKey)
            f.write(dsaKey.export_key(format='PEM'))
        elif keyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
            pass
        elif keyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
            rsaKey = RSA.import_key(extern_key=keyEntry.publicKey)
            f.write(rsaKey.export_key(format='PEM'))

        f.close()
    def listify(self):
        list = []
        for key,value in self.keyMap.items():
            for item in value:
                list.append(item)
        return list



class PrivateKeyRing(KeyRing):

    class PrivateKeyRingEntry:
        timestamp : datetime
        keyID : bytes
        publicKey : bytes
        encrtyptedPrivateKey : bytes
        userID : str
        algoTypeAsym : AlgoTypeAsym
        keySizeAsym : KeySizeAsym

        def __init__(self, publicKey : bytes, userID : str, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym,  encrtyptedPrivateKey : bytes) -> None:
            self.timestamp = datetime.datetime.now()
            self.keyID = publicKey[0:8]
            self.userID = userID
            self.publicKey = publicKey
            self.algoTypeAsym = algoTypeAsym
            self.keySizeAsym = keySizeAsym
            self.encrtyptedPrivateKey = encrtyptedPrivateKey


    def __generateKeyPairWithPrivateKey(self, private_key : bytes, public_key : bytes, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym, userData : UserData) -> PrivateKeyRingEntry:

        # Hash and Encrypt Key Pair
        h = SHA1.new()
        h.update(bytes(userData.password, 'utf-8'))
        hashed_password = h.digest()
        hashed_password = hashed_password[0:16]

        cryptedPrivateKey = CAST.new(hashed_password, CAST.MODE_OPENPGP).encrypt(private_key)

        privateKeyRingEntry : self.PrivateKeyRingEntry = self.PrivateKeyRingEntry(
            userID=userData.mail,
            algoTypeAsym=algoTypeAsym,
            publicKey=public_key,
            keySizeAsym=keySizeAsym,
            encrtyptedPrivateKey=cryptedPrivateKey
        )
        if userData.mail not in self.keyMap:
            self.keyMap[userData.mail] = []
        self.keyMap[userData.mail].append(privateKeyRingEntry)
        self.size += 1
        return privateKeyRingEntry

    def generateKeyPair(self, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym, userData : UserData) -> PrivateKeyRingEntry:

        private_key : bytes = None
        public_key : bytes = None

        if algoTypeAsym == AlgoTypeAsym.DSA:
            # Generate Key Pair
            key = DSA.generate(keySizeAsym.value)
            private_key = key.exportKey(format='DER')
            public_key = key.publickey().exportKey(format='DER')
        elif algoTypeAsym == AlgoTypeAsym.RSA:
            # Generate Key Pair
            key = RSA.generate(keySizeAsym.value)
            private_key = key.exportKey(format='DER')
            public_key = key.publickey().exportKey(format='DER')
        elif algoTypeAsym == AlgoTypeAsym.ELGAMAL:
            pass
            
        return self.__generateKeyPairWithPrivateKey(private_key=private_key, public_key=public_key, algoTypeAsym=algoTypeAsym, keySizeAsym=keySizeAsym, userData=userData)

    def exportPrivateKey(self, filePath : str ,keyID: bytes, password: str):
        f = open(file=filePath, mode='wb+')
        keyEntry = self.findEntryByKeyID(keyID=keyID)
        # Hash password
        h = SHA1.new()
        h.update(bytes(password, 'utf-8'))
        hashed_password = h.digest()
        hashed_password = hashed_password[0:16]

        # Decrypted key
        eiv = keyEntry.encrtyptedPrivateKey[:CAST.block_size+2]
        ciphertext = keyEntry.encrtyptedPrivateKey[CAST.block_size+2:]
        cipher = CAST.new(hashed_password, CAST.MODE_OPENPGP, eiv)
        privateKey = cipher.decrypt(ciphertext)
        if keyEntry.algoTypeAsym == AlgoTypeAsym.DSA:
            dsaKey = DSA.import_key(extern_key=privateKey)
            f.write(dsaKey.export_key(format='PEM'))
        elif keyEntry.algoTypeAsym == AlgoTypeAsym.ELGAMAL:
            pass
        elif keyEntry.algoTypeAsym == AlgoTypeAsym.RSA:
            rsaKey = RSA.import_key(extern_key=privateKey)
            f.write(rsaKey.export_key(format='PEM'))

        f.close()
    
    def importPrivateKey(self, filepathPublicKey: str, filepathPrivateKey: str, userID : str, password : str):
        fpublic = open(file=filepathPublicKey,mode='rb')
        fprivate = open(file=filepathPrivateKey,mode='rb')
        publicData = fpublic.read()
        privateData = fprivate.read()
        exceptionMsg = 'Keys are not of expected format!'
        try:
            keyPrivate = load_pem_private_key(privateData,password=None)
            keyPublic = load_pem_public_key(publicData)
            encrtyptedPrivateKey = None
            publicKey = None
            keySizeAsym = None
            algoTypeAsym = None
            if isinstance(keyPublic, rsa.RSAPublicKey) and isinstance(keyPrivate, rsa.RSAPrivateKey) and keyPrivate.key_size == keyPublic.key_size:
                publicKey = RSA.import_key(extern_key=publicData)
                keySizeAsym = KeySizeAsym(keyPublic.key_size)
                publicKey = publicKey.export_key(format='DER')
                algoTypeAsym = AlgoTypeAsym.RSA
                encrtyptedPrivateKey = RSA.import_key(extern_key=privateData)
                encrtyptedPrivateKey = encrtyptedPrivateKey.export_key(format='DER')
                h = SHA1.new()
                h.update(bytes(password, 'utf-8'))
                hashed_password = h.digest()
                hashed_password = hashed_password[0:16]
                encrtyptedPrivateKey = CAST.new(hashed_password, CAST.MODE_OPENPGP).encrypt(encrtyptedPrivateKey)
                
            elif isinstance(keyPublic, dsa.DSAPublicKey) and isinstance(keyPrivate, dsa.DSAPrivateKey) and keyPrivate.key_size == keyPublic.key_size:
                publicKey = DSA.import_key(extern_key=publicData)
                keySizeAsym = KeySizeAsym(keyPublic.key_size)
                publicKey = publicKey.export_key(format='DER')
                algoTypeAsym = AlgoTypeAsym.DSA
                encrtyptedPrivateKey = DSA.import_key(extern_key=privateData)
                encrtyptedPrivateKey = encrtyptedPrivateKey.export_key(format='DER')
                h = SHA1.new()
                h.update(bytes(password, 'utf-8'))
                hashed_password = h.digest()
                hashed_password = hashed_password[0:16]
                encrtyptedPrivateKey = CAST.new(hashed_password, CAST.MODE_OPENPGP).encrypt(encrtyptedPrivateKey)
            else:
                print('ELGAMAL')

            if userID not in self.keyMap:
                self.keyMap[userID] = []
            if self.findEntryByKeyID(publicKey[0:8]) == None:
                self.keyMap[userID].append(self.PrivateKeyRingEntry(
                    userID=userID,
                    algoTypeAsym=algoTypeAsym,
                    publicKey=publicKey,
                    keySizeAsym= keySizeAsym,
                    encrtyptedPrivateKey=encrtyptedPrivateKey
                ))
                self.size += 1
            else:
                exceptionMsg ='Key already exists!'
                raise(KeyError())
        except:
            raise(KeyError(exceptionMsg))
            
        fpublic.close()
        fprivate.close()



class PublicKeyRing(KeyRing):

    class PublicKeyRingEntry:
        timestamp : datetime
        keyID : bytes
        publicKey : bytes
        userID : str
        algoTypeAsym : AlgoTypeAsym
        keySizeAsym : KeySizeAsym

        def __init__(self, publicKey : bytes, userID : str, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym) -> None:
            self.timestamp = datetime.datetime.now()
            self.keyID = publicKey[0:8]
            self.userID = userID
            self.publicKey = publicKey
            self.algoTypeAsym = algoTypeAsym
            self.keySizeAsym = keySizeAsym



    def importSingleKey(self, publicKey : bytes, userID : str, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym):
        if userID not in self.keyMap:
            self.keyMap[userID] = []
        self.keyMap[userID].append(self.PublicKeyRingEntry(
            userID=userID,
            algoTypeAsym=algoTypeAsym,
            publicKey=publicKey,
            keySizeAsym=keySizeAsym
        ))
        self.size += 1
    
    def importPublicKey(self, filepath: str, userID : str):
        f = open(file=filepath,mode='rb')
        data = f.read()
        exceptionMsg = 'Key is not public!'
        try:
            key = load_pem_public_key(data)
            publicKey = None
            keySizeAsym = None
            algoTypeAsym = None
            if isinstance(key, rsa.RSAPublicKey):
                publicKey = RSA.import_key(extern_key=data)
                keySizeAsym = KeySizeAsym(key.key_size)
                publicKey = publicKey.export_key(format='DER')
                algoTypeAsym = AlgoTypeAsym.RSA
                
            elif isinstance(key, dsa.DSAPublicKey):
                publicKey = DSA.import_key(extern_key=data)
                keySizeAsym = KeySizeAsym(key.key_size)
                publicKey = publicKey.export_key(format='DER')
                algoTypeAsym = AlgoTypeAsym.DSA
            else:
                print('ELGAMAL')

            if userID not in self.keyMap:
                self.keyMap[userID] = []
            if self.findEntryByKeyID(publicKey[0:8]) == None:
                self.keyMap[userID].append(self.PublicKeyRingEntry(
                    userID=userID,
                    algoTypeAsym=algoTypeAsym,
                    publicKey=publicKey,
                    keySizeAsym= keySizeAsym
                ))
                self.size += 1
            else:
                exceptionMsg ='Key already exists!'
                raise(KeyError())
        except:
            raise(KeyError(exceptionMsg))
            
        f.close()
        
    

    