# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\ui\messageRecieve.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QMessageBox
import globals

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(800, 600)
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(70, 40, 100, 50))
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(70, 130, 661, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.textBrowser = QtWidgets.QTextBrowser(Form)
        self.textBrowser.setGeometry(QtCore.QRect(60, 210, 671, 191))
        self.textBrowser.setObjectName("textBrowser")
        self.textBrowser.setText(globals.message)
        self.pushButton_3 = QtWidgets.QPushButton(Form)
        self.pushButton_3.setGeometry(QtCore.QRect(20, 540, 120, 40))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_3.setFont(font)
        self.pushButton_3.clicked.connect(self.button_handler_back)
        self.pushButton_3.setObjectName("pushButton_3")
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setGeometry(QtCore.QRect(280, 420, 231, 61))
        self.pushButton_2.clicked.connect(self.button_handler_saveFile)
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.label_3 = QtWidgets.QLabel(Form)
        self.label_3.setGeometry(QtCore.QRect(160, 40, 611, 50))
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")

        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("PGP", "PGP"))

        if globals.pgpOptions.signature:
            self.label_2.setText(_translate("Form", "MESSAGE IS AUTHENTIC!"))
            self.label.setText(_translate("Form", "From:"))
            self.label_3.setText(_translate("Form", globals.email))
        else:
            self.label_2.setText(_translate("Form", ""))
            self.label.setText(_translate("Form", ""))
            self.label_3.setText(_translate("Form", ""))
        self.pushButton_3.setText(_translate("Form", "Back"))
        self.pushButton_2.setText(_translate("Form", "Save File"))
        


    def button_handler_back(self):
        self.window = QtWidgets.QMainWindow()
        self.ui = homeUI()
        self.ui.setupUi(self.window)
        globals.currentWindow.hide()
        globals.currentWindow = self.window
        self.window.show()

    def button_handler_saveFile(self):
         filePath, enteredFilePath = QtWidgets.QInputDialog.getText(globals.currentWindow, 'File Path', 'Enter file path:')
         if(enteredFilePath):
            try:
                f = open(filePath, 'w+')
                f.write(globals.message)
                f.close()
                msg = QMessageBox(globals.currentWindow)
                msg.setWindowTitle("SUCCESS!")
                msg.setText("FILE SAVED!")
                msg.exec()
            except:
                msg = QMessageBox(globals.currentWindow)
                msg.setWindowTitle("FILE PATH ERROR!")
                msg.setText("INVALID FILE PATH!")
                msg.exec()




from home import Ui_Form as homeUI