from KeyRing import PrivateKeyRing
from User import *
import time


def main():
    userData = UserData()
    userData.mail = "veljkolazic2000@gmail.com"
    userData.password = "malikurac123"
    userData.name = "Veljko Djadjic"

    userData1 = UserData()
    userData1.mail = "zaza2000@gmail.com"
    userData1.password = "ioajsdijas"
    userData1.name = "Macici Macici"

    userData2 = UserData()
    userData2.mail = "fedja2000@gmail.com"
    userData2.password = "ioajsdijas"
    userData2.name = "Franjo Macici"

    generator = PrivateKeyRing()

    generator.generateKeyPair(algoTypeAsym = AlgoTypeAsym.DSA, keySizeAsym = KeySizeAsym.KEY1024, userData = userData)
    generator.generateKeyPair(algoTypeAsym = AlgoTypeAsym.RSA, keySizeAsym = KeySizeAsym.KEY1024, userData = userData1)
    # generator.generateKeyPair(algoTypeAsym = AlgoTypeAsym.ELGAMAL, keySizeAsym = KeySizeAsym.KEY1024, userData = userData2)

    print(str(generator))

if __name__=="__main__":
    main()