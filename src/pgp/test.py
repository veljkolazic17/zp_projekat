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
    pgp.privateKeyRing.importPrivateKey(filepathPrivateKey='privateKey.pem',filepathPublicKey='kljuc.pem',userID='veljkolazic2000@gmail.com',password='malikurac123')
    pgp.publicKeyRing.importPublicKey(filepath='kljuc.pem',userID='veljkolazic2000@gmail.com')
    #privateKeyEnyty = pgp.privateKeyRing.generateKeyPair(algoTypeAsym = AlgoTypeAsym.DSA, keySizeAsym = KeySizeAsym.KEY1024, userData = userData)
    #pgp.publicKeyRing.importSingleKey(userID=privateKeyEnyty.userID, publicKey=privateKeyEnyty.publicKey, algoTypeAsym=AlgoTypeAsym.DSA, keySizeAsym=privateKeyEnyty.keySizeAsym)
    #pgp.sendMessage(message=b'kurvicamalaslatka', filePath='kurac.txt', pgpoptions=PGPOptions(signature=True,zip=True,radix64=True),password='malikurac123', privateKeyEntry=pgp.privateKeyRing.keyMap['veljkolazic2000@gmail.com'][0], publicKeyEntry=pgp.publicKeyRing.keyMap['veljkolazic2000@gmail.com'][0], algotTypeSym=AlgoTypeSym.AES128)
    pgp.receiveMessage(filePath='asd', password='malikurac123')
    #pgp.privateKeyRing.exportPublicKey(filePath='kljuc.pem',keyID=privateKeyEnyty.keyID)
    #pgp.privateKeyRing.exportPrivateKey(filePath='privateKey.pem', keyID=privateKeyEnyty.keyID, password='malikurac123')
   
    print(pgp.publicKeyRing)

if __name__=="__main__":
    main()