import sys
sys.path.insert(1, 'src/pgp')
import PGP
sys.path.append('..')
from PyQt5 import QtCore, QtGui, QtWidgets
from sendMessage1 import Ui_Form as sendMessage1UI
from home import Ui_Form as homeUI

import globals

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)    
    Form = QtWidgets.QWidget()
    globals.currentWindow = Form
    globals.pgpOptions = PGP.PGPOptions()
    globals.pgp = PGP.PGP()
    ui = homeUI()
    ui.setupUi(Form)
    globals.currentWindow.show()
    sys.exit(app.exec_())