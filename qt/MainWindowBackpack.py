# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindowBackpack.ui'
#
# Created by: PyQt5 UI code generator 5.15.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(600, 549)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(10, 10, 581, 31))
        self.label.setStyleSheet("font: 14pt \"Times New Roman\";")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.pushButton = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton.setGeometry(QtCore.QRect(10, 340, 581, 51))
        self.pushButton.setStyleSheet("font: 12pt \"Times New Roman\";")
        self.pushButton.setObjectName("pushButton")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(110, 270, 21, 16))
        self.label_2.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(320, 270, 21, 16))
        self.label_3.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(10, 140, 581, 23))
        self.label_4.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_4.setAlignment(QtCore.Qt.AlignCenter)
        self.label_4.setObjectName("label_4")
        self.plainTextEdit_4 = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit_4.setGeometry(QtCore.QRect(110, 180, 381, 31))
        self.plainTextEdit_4.setObjectName("plainTextEdit_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(20, 230, 561, 23))
        self.label_5.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_5.setAlignment(QtCore.Qt.AlignCenter)
        self.label_5.setObjectName("label_5")
        self.plainTextEdit_5 = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit_5.setGeometry(QtCore.QRect(130, 260, 151, 31))
        self.plainTextEdit_5.setObjectName("plainTextEdit_5")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(10, 50, 581, 23))
        self.label_6.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_6.setAlignment(QtCore.Qt.AlignCenter)
        self.label_6.setObjectName("label_6")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(10, 80, 581, 23))
        self.label_7.setStyleSheet("font: 10pt \"Times New Roman\";")
        self.label_7.setAlignment(QtCore.Qt.AlignCenter)
        self.label_7.setObjectName("label_7")
        self.plainTextEdit_6 = QtWidgets.QPlainTextEdit(self.centralwidget)
        self.plainTextEdit_6.setGeometry(QtCore.QRect(340, 260, 151, 31))
        self.plainTextEdit_6.setObjectName("plainTextEdit_6")
        self.pushButton_2 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_2.setGeometry(QtCore.QRect(10, 440, 231, 51))
        self.pushButton_2.setStyleSheet("font: 12pt \"Times New Roman\";")
        self.pushButton_2.setObjectName("pushButton_2")
        self.pushButton_3 = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_3.setGeometry(QtCore.QRect(360, 440, 231, 51))
        self.pushButton_3.setStyleSheet("font: 12pt \"Times New Roman\";")
        self.pushButton_3.setObjectName("pushButton_3")
        MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "Шифрация методом упаковки рюкзака"))
        self.pushButton.setText(_translate("MainWindow", "Получить открытый ключ"))
        self.label_2.setText(_translate("MainWindow", "S="))
        self.label_3.setText(_translate("MainWindow", "N="))
        self.label_4.setText(_translate("MainWindow", "Введите сверхвозрастающую последовательность"))
        self.label_5.setText(_translate("MainWindow", "Введите секретное число S и модуль N"))
        self.label_6.setText(_translate("MainWindow", "Для выбора секретного ключа введите сверхвозрастающую "))
        self.label_7.setText(_translate("MainWindow", "последовательность из 10 чисел, секретное число S и модуль N"))
        self.pushButton_2.setText(_translate("MainWindow", "Шифрация"))
        self.pushButton_3.setText(_translate("MainWindow", "Дешифрация"))
