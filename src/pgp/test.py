from KeyRing import PrivateKeyRing
from User import *
from PGP import *

def main():
    userData = UserData()
    userData.mail = "veljkolazic2000@gmail.com"
    userData.password = "123"
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
    pgp.privateKeyRing.importPrivateKey(filepathPrivateKey='privateKey.pem',filepathPublicKey='kljuc.pem',userID='veljkolazic2000@gmail.com',password='123')
    pgp.publicKeyRing.importPublicKey(filepath='kljuc.pem',userID='veljkolazic2000@gmail.com')

   
    print(pgp.publicKeyRing)

if __name__=="__main__":
    main()