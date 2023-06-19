import sys
sys.path.insert(1, 'src/pgp')
sys.path.append('..')
import PGP
import User
from PyQt5 import QtCore, QtGui, QtWidgets
from sendMessage1 import Ui_Form as sendMessage1UI
from home import Ui_Form as homeUI

import globals

if __name__ == "__main__":
    userData = User.UserData()
    userData.mail = "veljkolazic2000@gmail.com"
    userData.password = "123"
    userData.name = "Veljko Djadjic"
   
    import sys
    app = QtWidgets.QApplication(sys.argv)    
    Form = QtWidgets.QWidget()
    globals.algoAsymEncryption = None
    globals.algoAsymSignature = None
    globals.algoSym = None
    globals.message = ""
    globals.filePath = ""
    globals.privateKeyEntry = None
    globals.publicKeyEntry = None
    globals.previousRowPrivate = None
    globals.previousRowPublic = None
    globals.currentWindow = Form
    globals.pgpOptions = PGP.PGPOptions()
    globals.pgp = PGP.PGP()

    ui = homeUI()
    ui.setupUi(Form)
    globals.currentWindow.show()
    sys.exit(app.exec_())