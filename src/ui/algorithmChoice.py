# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\ui\algorithmChoice.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import globals
import sys
sys.path.insert(1, 'src/pgp')
import User
sys.path.append('..')

class Ui_AlgorithmForm(object):
    def setupUi(self, AlgorithmForm):
        AlgorithmForm.setObjectName("AlgorithmForm")
        AlgorithmForm.resize(800, 600)
        self.verticalLayoutWidget = QtWidgets.QWidget(AlgorithmForm)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(80, 150, 651, 121))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(3)
        self.verticalLayout.setObjectName("verticalLayout")
        self.dsa_elgamal = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(30)
        sizePolicy.setVerticalStretch(30)
        sizePolicy.setHeightForWidth(self.dsa_elgamal.sizePolicy().hasHeightForWidth())
        self.dsa_elgamal.setSizePolicy(sizePolicy)
        self.dsa_elgamal.setMinimumSize(QtCore.QSize(30, 30))
        self.dsa_elgamal.setBaseSize(QtCore.QSize(30, 30))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.dsa_elgamal.setFont(font)
        self.dsa_elgamal.setIconSize(QtCore.QSize(100, 100))
        self.dsa_elgamal.setChecked(True)
        self.dsa_elgamal.setObjectName("dsa_elgamal")
        self.verticalLayout.addWidget(self.dsa_elgamal)
        self.rsa_rsa = QtWidgets.QRadioButton(self.verticalLayoutWidget)
        font = QtGui.QFont()
        font.setPointSize(15)
        self.rsa_rsa.setFont(font)
        self.rsa_rsa.setObjectName("rsa_rsa")
        self.verticalLayout.addWidget(self.rsa_rsa)
        self.label = QtWidgets.QLabel(AlgorithmForm)
        self.label.setGeometry(QtCore.QRect(80, 40, 649, 101))
        font = QtGui.QFont()
        font.setPointSize(30)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(AlgorithmForm)
        self.pushButton.setGeometry(QtCore.QRect(20, 540, 120, 40))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(AlgorithmForm)
        self.pushButton_2.setGeometry(QtCore.QRect(660, 540, 120, 40))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        if globals.pgpOptions.encryption:
            self.verticalLayoutWidget_2 = QtWidgets.QWidget(AlgorithmForm)
            self.verticalLayoutWidget_2.setGeometry(QtCore.QRect(80, 360, 651, 121))
            self.verticalLayoutWidget_2.setObjectName("verticalLayoutWidget_2")
            self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_2)
            self.verticalLayout_2.setSizeConstraint(QtWidgets.QLayout.SetNoConstraint)
            self.verticalLayout_2.setContentsMargins(0, 0, 0, 0)
            self.verticalLayout_2.setSpacing(3)
            self.verticalLayout_2.setObjectName("verticalLayout_2")
            self.aes128 = QtWidgets.QRadioButton(self.verticalLayoutWidget_2)
            sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Fixed)
            sizePolicy.setHorizontalStretch(30)
            sizePolicy.setVerticalStretch(30)
            sizePolicy.setHeightForWidth(self.aes128.sizePolicy().hasHeightForWidth())
            self.aes128.setSizePolicy(sizePolicy)
            self.aes128.setMinimumSize(QtCore.QSize(30, 30))
            self.aes128.setBaseSize(QtCore.QSize(30, 30))
            font = QtGui.QFont()
            font.setPointSize(15)
            self.aes128.setFont(font)
            self.aes128.setIconSize(QtCore.QSize(100, 100))
            self.aes128.setChecked(True)
            self.aes128.setObjectName("aes128")
            self.verticalLayout_2.addWidget(self.aes128)
            self.cast5 = QtWidgets.QRadioButton(self.verticalLayoutWidget_2)
            font = QtGui.QFont()
            font.setPointSize(15)
            self.cast5.setFont(font)
            self.cast5.setObjectName("cast5")
            self.verticalLayout_2.addWidget(self.cast5)
            self.label_2 = QtWidgets.QLabel(AlgorithmForm)
            self.label_2.setGeometry(QtCore.QRect(70, 320, 361, 41))
            font = QtGui.QFont()
            font.setPointSize(15)
            font.setBold(True)
            font.setWeight(75)
            self.label_2.setFont(font)
            self.label_2.setAlignment(QtCore.Qt.AlignCenter)
            self.label_2.setObjectName("label_2")

        self.retranslateUi(AlgorithmForm)
        QtCore.QMetaObject.connectSlotsByName(AlgorithmForm)

    def retranslateUi(self, AlgorithmForm):
        _translate = QtCore.QCoreApplication.translate
        AlgorithmForm.setWindowTitle(_translate("AlgorithmForm", "Form"))

        if globals.pgpOptions.encryption and globals.pgpOptions.signature:
            self.label.setText(_translate("AlgorithmForm", "Signature/Encryption algorithm"))
            self.dsa_elgamal.setText(_translate("AlgorithmForm", "DSA/ELGAMAL"))
            self.rsa_rsa.setText(_translate("AlgorithmForm", "RSA/RSA"))
            self.aes128.setText(_translate("AlgorithmForm", "AES128"))
            self.cast5.setText(_translate("AlgorithmForm", "CAST5"))
            self.label_2.setText(_translate("AlgorithmForm", "Symmetric encryption algorithm:"))
        elif globals.pgpOptions.encryption:
            self.label.setText(_translate("AlgorithmForm", "Encryption algorithm"))
            self.dsa_elgamal.setText(_translate("AlgorithmForm", "ELGAMAL"))
            self.rsa_rsa.setText(_translate("AlgorithmForm", "RSA"))
            self.aes128.setText(_translate("AlgorithmForm", "AES128"))
            self.cast5.setText(_translate("AlgorithmForm", "CAST5"))
            self.label_2.setText(_translate("AlgorithmForm", "Symmetric encryption algorithm:"))
        elif globals.pgpOptions.signature:
            self.label.setText(_translate("AlgorithmForm", "Signature algorithm"))
            self.dsa_elgamal.setText(_translate("AlgorithmForm", "DSA"))
            self.rsa_rsa.setText(_translate("AlgorithmForm", "RSA"))

        self.pushButton.setText(_translate("AlgorithmForm", "Back"))
        self.pushButton.clicked.connect(self.button_handler_sendMessageBack)
        self.pushButton_2.setText(_translate("AlgorithmForm", "Next"))
        self.pushButton_2.clicked.connect(self.button_handler_sendMessageNext)
    
    def button_handler_sendMessageBack(self):
        self.window = QtWidgets.QMainWindow()
        self.ui = sendMessageUI()
        self.ui.setupUi(self.window)
        globals.currentWindow.hide()
        globals.currentWindow = self.window
        self.window.show()

    def button_handler_sendMessageNext(self):

        if globals.pgpOptions.signature:
            globals.algoAsymSignature = User.AlgoTypeAsym.DSA if self.dsa_elgamal.isChecked() else User.AlgoTypeAsym.RSA
        if globals.pgpOptions.encryption:
            globals.algoAsymEncryption = User.AlgoTypeAsym.ELGAMAL if self.dsa_elgamal.isChecked() else User.AlgoTypeAsym.RSA
            globals.algoSym = User.AlgoTypeSym.AES128 if self.aes128.isChecked() else User.AlgoTypeSym.CAST5

        self.window = QtWidgets.QMainWindow()
        self.ui = keySelectionUI()
        self.ui.setupUi(self.window)
        globals.currentWindow.hide()
        globals.currentWindow = self.window
        self.window.show()


from sendMessage1 import Ui_Form as sendMessageUI
from keySelection import Ui_Form as keySelectionUI