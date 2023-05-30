import datetime

from User import *

from Crypto.PublicKey import DSA
from Crypto.PublicKey import RSA
from Crypto.Cipher import CAST
from Crypto.Hash import SHA1

class PrivateKeyRing:

    class PrivateKeyRingEntry:
        timestamp : datetime
        keyID : bytes
        publicKey : bytes
        encrtyptedPrivateKey : bytes
        userID : str
        algoTypeAsym : AlgoTypeAsym
        keySizeAsym : KeySizeAsym


    def __generateKeyPairWithPrivateKey(self, private_key : bytes, public_key : bytes, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym, userData : UserData) -> PrivateKeyRingEntry:
        privateKeyRingEntry = self.PrivateKeyRingEntry()

        # Hash and Encrypt Key Pair
        h = SHA1.new()
        h.update(bytes(userData.password, 'utf-8'))
        hashed_password = h.digest()
        hashed_password = hashed_password[0:16]

        cryptedPassword = CAST.new(hashed_password, CAST.MODE_OPENPGP).encrypt(private_key)
        
        privateKeyRingEntry.encrtyptedPrivateKey = cryptedPassword
        privateKeyRingEntry.publicKey = public_key
        privateKeyRingEntry.keyID = privateKeyRingEntry.publicKey[0:8]
        privateKeyRingEntry.timestamp = datetime.datetime.now()
        privateKeyRingEntry.userID = userData.mail
        privateKeyRingEntry.algoTypeAsym = algoTypeAsym
        privateKeyRingEntry.keySizeAsym = keySizeAsym


        if privateKeyRingEntry.userID not in self.keyMap:
            self.keyMap[privateKeyRingEntry.userID] = []
        self.keyMap[privateKeyRingEntry.userID].append(privateKeyRingEntry)

        return privateKeyRingEntry


    def __init__(self) -> None:
        self.keyMap = {} 

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

    def findEntryByKeyID(self, keyID : bytes) -> PrivateKeyRingEntry:
        for _, value in self.keyMap.items():
            for entry in value:
                if entry.keyID == keyID:
                    return entry
        return None
                
    def importKeyPair():
        pass

    def __str__(self) -> str:
        res : str = ""
        for key in self.keyMap.keys():
            for entry in self.keyMap[key]:
                res += entry.userID + " " + str(entry.keyID)
            res += '\n'
        return res

class PublicKeyRing:

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

    def __init__(self) -> None:
        self.keyMap = {} 

    def __str__(self) -> str:
        res : str = ""
        for key in self.keyMap.keys():
            for entry in self.keyMap[key]:
                res += entry.userID + " " + str(entry.keyID)
            res += '\n'
        return res

    def importSingleKey(self, publicKey : bytes, userID : str, algoTypeAsym : AlgoTypeAsym, keySizeAsym : KeySizeAsym):
        if userID not in self.keyMap:
            self.keyMap[userID] = []
        self.keyMap[userID].append(self.PublicKeyRingEntry(
            userID=userID,
            algoTypeAsym=algoTypeAsym,
            publicKey=publicKey,
            keySizeAsym=keySizeAsym
        ))
    
    def findEntryByKeyID(self, keyID : bytes) -> PublicKeyRingEntry:
        for _, value in self.keyMap.items():
            for entry in value:
                if entry.keyID == keyID:
                    return entry
        return None

    