import sys
sys.path.insert(1, 'src/pgp')
import PGP
import User
sys.path.append('..')
from PyQt5 import QtCore, QtGui, QtWidgets
from sendMessage1 import Ui_Form as sendMessage1UI
from home import Ui_Form as homeUI

import globals

if __name__ == "__main__":
    userData = User.UserData()
    userData.mail = "veljkolazic2000@gmail.com"
    userData.password = "malikurac123"
    userData.name = "Veljko Djadjic"
   
    import sys
    app = QtWidgets.QApplication(sys.argv)    
    Form = QtWidgets.QWidget()
    globals.currentWindow = Form
    globals.pgpOptions = PGP.PGPOptions()
    globals.pgp = PGP.PGP()
    globals.pgp.privateKeyRing.importPrivateKey(filepathPrivateKey='privateKey.pem',filepathPublicKey='kljuc.pem',userID='veljkolazic2000@gmail.com',password='malikurac123')
    globals.pgp.publicKeyRing.importPublicKey(filepath='kljuc.pem',userID='veljkolazic2000@gmail.com')
    ui = homeUI()
    ui.setupUi(Form)
    globals.currentWindow.show()
    sys.exit(app.exec_())