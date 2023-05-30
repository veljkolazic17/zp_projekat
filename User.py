from enum import Enum

# class AlgoPairTypeAsym(Enum):
#     RSARSA = 1
#     DSAELGAMAL = 2

class AlgoTypeAsym(Enum):
    NONE = 0
    RSA = 1
    DSA = 2
    ELGAMAL = 3

class AlgoTypeSym(Enum):
    NONE = 0
    CAST5 = 1
    AES128 = 2

class KeySizeAsym(Enum):
    KEY1024 = 1024
    KEY2048 = 2048

class UserData:
    name : str
    mail : str
    password : str


