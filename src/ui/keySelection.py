# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '.\src\ui\keySelection.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
import globals
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtWidgets import QAbstractItemView
class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.setEnabled(True)
        Form.resize(800, 600)
        self.label = QtWidgets.QLabel(Form)
        self.label.setGeometry(QtCore.QRect(40, 60, 301, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Form)
        self.label_2.setGeometry(QtCore.QRect(450, 60, 301, 41))
        font = QtGui.QFont()
        font.setPointSize(15)
        font.setBold(True)
        font.setWeight(75)
        self.label_2.setFont(font)
        self.label_2.setAlignment(QtCore.Qt.AlignCenter)
        self.label_2.setObjectName("label_2")
        self.privateKeys = QtWidgets.QTableWidget(Form)
        self.privateKeys.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        
        self.privateKeys.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.privateKeys.setSelectionBehavior(QAbstractItemView.SelectRows)
        if not globals.pgpOptions.signature:
            self.privateKeys.setEnabled(False)
        self.privateKeys.setGeometry(QtCore.QRect(40, 110, 300, 411))
        self.privateKeys.setObjectName("privateKeys")
        self.privateKeys.setColumnCount(5)
        self.privateKeys.setRowCount(globals.pgp.privateKeyRing.size)
        self.publicKeys = QtWidgets.QTableWidget(Form)
        self.publicKeys.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.publicKeys.resizeColumnsToContents()
        self.publicKeys.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        self.publicKeys.setSelectionBehavior(QAbstractItemView.SelectRows)
        if not globals.pgpOptions.encryption:
            self.publicKeys.setEnabled(False)
        self.publicKeys.setGeometry(QtCore.QRect(450, 110, 300, 411))
        self.publicKeys.setObjectName("publicKeys")
        self.publicKeys.setColumnCount(5)
        self.publicKeys.setRowCount(globals.pgp.publicKeyRing.size)
        self.pushButton = QtWidgets.QPushButton(Form)
        self.pushButton.setGeometry(QtCore.QRect(20, 540, 120, 40))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton.setFont(font)
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(Form)
        self.pushButton_2.setGeometry(QtCore.QRect(660, 540, 120, 40))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.pushButton_2.setFont(font)
        self.pushButton_2.setObjectName("pushButton_2")
        self.retranslateUi(Form)
        QtCore.QMetaObject.connectSlotsByName(Form)

    def button_handler_sendMessageBack(self):
        self.window = QtWidgets.QMainWindow()
        self.ui = algoUI()
        self.ui.setupUi(self.window)
        globals.currentWindow.hide()
        globals.currentWindow = self.window
        self.window.show()

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label.setText(_translate("Form", "Private Key Selection"))
        self.label_2.setText(_translate("Form", "Public Key Selection"))
        self.pushButton.setText(_translate("Form", "Back"))
        self.pushButton.clicked.connect(self.button_handler_sendMessageBack)
        self.pushButton_2.setText(_translate("Form", "Next"))
        list = globals.pgp.privateKeyRing.listify()
        self.privateKeys.setHorizontalHeaderLabels([
            "Timestamp",
            "KeyID",
            "User ID",
            "Algo Type",
            "Key Size"
        ])
        for i in range(globals.pgp.privateKeyRing.size):
            secondList = [list[i].timestamp, list[i].keyID.hex(), list[i].userID, list[i].algoTypeAsym, list[i].keySizeAsym.value]
            for j in range(5):
                self.privateKeys.setItem(i,j, QTableWidgetItem(str(secondList[j])))
        self.privateKeys.resizeColumnsToContents()
        list = globals.pgp.publicKeyRing.listify()
        self.publicKeys.setHorizontalHeaderLabels([
            "Timestamp",
            "KeyID",
            "User ID",
            "Algo Type",
            "Key Size"
        ])
        for i in range(globals.pgp.publicKeyRing.size):
            secondList = [list[i].timestamp, list[i].keyID.hex(), list[i].userID, list[i].algoTypeAsym, list[i].keySizeAsym.value]
            for j in range(5):
                self.publicKeys.setItem(i,j, QTableWidgetItem(str(secondList[j])))
        self.publicKeys.resizeColumnsToContents()
               

from algorithmChoice import Ui_AlgorithmForm as algoUI

