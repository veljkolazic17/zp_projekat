from KeyRing import PrivateKeyRing
from User import *
from PGP import *

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

    pgp = PGP()
    pgp.privateKeyRing.generateKeyPair(algoTypeAsym = AlgoTypeAsym.RSA, keySizeAsym = KeySizeAsym.KEY1024, userData = userData)
    pgp.sendMessage(message=b'kurvicamalaslatka', filePath='kurac', pgpoptions=PGPOptions(encryption=True),password='malikurac123', privateKeyEntry=pgp.privateKeyRing.keyMap['veljkolazic2000@gmail.com'][0], algotTypeSym=AlgoTypeSym.AES128)


if __name__=="__main__":
    main()