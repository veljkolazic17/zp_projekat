from enum import Enum

# class AlgoPairTypeAsym(Enum):
#     RSARSA = 1
#     DSAELGAMAL = 2

class AlgoTypeAsym(Enum):
    NONE = 0
    RSA = 1
    DSA = 2
    ELGAMAL = 3

    def __str__(self) -> str:
        if self.value == 1:
            return "RSA"
        if self.value == 2:
            return "DSA"
        if self.value == 3:
            return "ELGAMAL"
        return "NONE"

class AlgoTypeSym(Enum):
    NONE = 0
    CAST5 = 1
    AES128 = 2

class KeySizeAsym(Enum):
    NONE = 0
    KEY1024 = 1024
    KEY2048 = 2048

class UserData:
    name : str
    mail : str
    password : str


