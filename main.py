import sys
import copy
from PyQt5 import QtWidgets
from qt import MainWindowBackpack, DecryptionWindowBackpack, EncryptionWindowBackpack, ErrorWindowBackpack, SuccessWindowBackpack, PublicKeyWindowBackpack


def bezout(a, b):
    '''An implementation of extended Euclidean algorithm.
    Returns integer x, y and gcd(a, b) for Bezout equation:
        ax + by = gcd(a, b).
    '''
    x, xx, y, yy = 1, 0, 0, 1
    while b:
        q = a // b
        a, b = b, a % b
        x, xx = xx, x - xx * q
        y, yy = yy, y - yy * q
    return y


class Backpack:
    def __init__(self):
        self.secret_key = list()
        self.public_key = list()
        self.N = 0
        self.S = 0

    def get_secret_key(self):
        return self.secret_key

    def set_secret_key(self, secret_key):
        self.secret_key = copy.deepcopy(secret_key)

    def set_N(self, N):
        self.N = N

    def set_S(self, S):
        self.S = S

    def generate_public_key(self):
        for item in self.secret_key:
            buf = (self.S * item) % self.N
            self.public_key.append(buf)

    def get_public_key(self):
        return self.public_key

    def set_public_key(self, public_key):
        self.public_key = copy.deepcopy(public_key)

    # number must be a string, that contains binary format of data
    def encrypt_number(self, number):
        print(number)
        encrypt_message = list()
        buf = 0
        for i in range(1, len(number) + 1):
            if number[i - 1] == '0':
                if i % len(self.public_key) == 0:
                    encrypt_message.append(buf)
                    buf = 0

            if number[i - 1] == '1':
                buf_index = (i - 1) % len(self.public_key)
                buf += self.public_key[((i - 1) % len(self.public_key))]
                if i % len(self.public_key) == 0:
                    encrypt_message.append(buf)
                    buf = 0
        if buf != 0:
            encrypt_message.append(buf)
        print(encrypt_message)
        return encrypt_message

    def decrypt_number(self, number):
        inverse_S = bezout(self.N, self.S)
        # weight = encrypted_symbol * inverse_S % self.N
        decrypt_message = list()
        for i in range(0, len(number)):
            weight = number[i] * inverse_S % self.N
            count = len(self.secret_key)
            buf = ""
            while count != 0:
                if weight >= self.secret_key[count - 1]:
                    weight -= self.secret_key[count - 1]
                    buf += '1'
                else:
                    buf += '0'
                count -= 1
            decrypt_message.append(buf)
        print(decrypt_message)
        return decrypt_message
        # reverse_decrypt_message = ""
        # for item in decrypt_message:
        #     string_buf = "".join(reversed(item))
        #     reverse_decrypt_message += string_buf
        # print(reverse_decrypt_message)
        # num_to_str = ''.join(format(ord(i), 'b') for i in number)
        # len_num_to_str = len(num_to_str)
        # len_secret_key = len(self.secret_key)
        # padding = len_num_to_str % len_secret_key
        # final_str = ""
        # final_len = len_num_to_str + (len_secret_key - padding)
        # print(final_len)
        # final_str = num_to_str.rjust(final_len, '0')
        # print(padding)
        # print(final_str)
        # print(len(final_str))
        # encrypt_message = list()
        # buf = 0;
        # for i in range(0, len(final_str)):
        #     if final_str[i] == 1:
        #         buf += self.public_key[i % len(self.public_key)]
        #         if i % len(self.public_key):
        #             encrypt_message.append(buf)
        #             buf = 0


class BackpackAppMain(QtWidgets.QMainWindow, MainWindowBackpack.Ui_MainWindow):
    def show_error_window(self, error_text):
        self.errorWindow.plainTextEdit_5.appendPlainText(error_text)
        self.errorWindow.show()

    def show_decryption_window(self):
        self.decryptionWindow.show()

    def show_encryption_window(self):
        self.encryptionWindow.show()

    def show_publickey_window(self):
        try:
            secret_key = self.get_input_secret_key()
            N = self.get_input_N()
            S = self.get_input_S()
            if secret_key is None or N is None or S is None:
                print("ANTA BAKA?! CHECK USER INPUT")
            else:
                backpack = Backpack()
                backpack.set_N(N)
                backpack.set_S(S)
                self.backpack.set_S(S)
                self.backpack.set_N(N)
                backpack.set_secret_key(secret_key)
                backpack.generate_public_key()
                public_key = backpack.get_public_key()
                print(public_key)
                public_key = [str(item) for item in public_key]
                public_key_string = ' '.join(public_key)
                print(public_key_string)
                self.publickeyWindow.update_text(public_key_string)
                self.publickeyWindow.show()
        except:
            self.show_error_window("Невозможно сгенерировать публичный ключ")

    def get_input_secret_key(self):
        try:
            text = self.plainTextEdit_4.toPlainText()
            secret_key = text.split(' ', 10)
            secret_key = [int(item) for item in secret_key]
            return secret_key
        except:
            self.show_error_window("Неправильно введен секретный ключ")

    def get_input_S(self):
        try:
            text = self.plainTextEdit_5.toPlainText()
            S = int(text)
            return S
        except:
            self.show_error_window("Неправильно введено секретное число S")

    def get_input_N(self):
        try:
            text = self.plainTextEdit_6.toPlainText()
            N = int(text)
            return N
        except:
            self.show_error_window("Неправильно введен модуль N")

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.plainTextEdit_4.setPlaceholderText('10 чисел через пробел (num_1 num2 ... num10)')
        self.plainTextEdit_5.setPlaceholderText('число')
        self.plainTextEdit_6.setPlaceholderText('число')
        self.errorWindow = BackpackAppError()
        self.encryptionWindow = BackpackAppEncrypt()
        self.decryptionWindow = BackpackAppDecrypt()
        self.publickeyWindow = BackpackAppPublicKey()
        self.backpack = Backpack()
        self.pushButton.clicked.connect(self.show_publickey_window)
        self.pushButton_2.clicked.connect(self.show_encryption_window)
        self.pushButton_3.clicked.connect(self.show_decryption_window)


class BackpackAppEncrypt(QtWidgets.QMainWindow, EncryptionWindowBackpack.Ui_MainWindow):
    def encrypt(self):
        try:
            number = self.get_input_number()
            public_key = self.get_input_publickkey()
            backpack = Backpack()
            backpack.set_public_key(public_key)
            encrypt_message = backpack.encrypt_number(number)
            if public_key is None or number is None or encrypt_message is None:
                print("ANTA BAKA?! CHECK USER INPUT")
            else:
                encrypt_message_final = [str(item) for item in encrypt_message]
                final_string = ' '.join(encrypt_message_final)  # ''
                self.success_window.update_text(final_string)
                self.success_window.show()
        except:
            self.error_window.update_text("Что-то пошло не так ...")
            self.error_window.show()

    def get_input_publickkey(self):
        try:
            text = self.plainTextEdit_5.toPlainText()
            public_key = text.split(' ', 10)
            public_key = [int(item) for item in public_key]
            print(public_key)
            return public_key
        except:
            self.error_window.update_text("Неправильно введен открытый ключ")
            self.error_window.show()

    def get_input_number(self):
        try:
            text = self.plainTextEdit_4.toPlainText()
            print(text)
            return text
        except:
            self.error_window.update_text("Неправильно введено число")
            self.error_window.show()

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.error_window = BackpackAppError()
        self.success_window = BackpackAppSuccess()
        self.plainTextEdit_4.setPlaceholderText('число в бинарном формате (10...01)')
        self.plainTextEdit_5.setPlaceholderText('10 чисел через пробел (num_1 num2 ... num10)')
        self.pushButton.clicked.connect(self.encrypt)


class BackpackAppDecrypt(QtWidgets.QMainWindow, DecryptionWindowBackpack.Ui_MainWindow):
    def decrypt(self):
        try:
            number = self.get_input_number()
            secret_key = self.get_input_secretkey()
            backpack = Backpack()
            backpack.set_secret_key(secret_key)
            app_main.backpack.set_secret_key(secret_key)
            decrypt_message = app_main.backpack.decrypt_number(number)
            if secret_key is None or number is None or decrypt_message is None:
                print("ANTA BAKA?! CHECK USER INPUT")
            else:
                decrypt_message_final = [str(item) for item in decrypt_message]
                final_string = ''.join(decrypt_message_final)  # ''
                self.success_window.update_text(final_string )
                self.success_window.show()
        except:
            self.error_window.update_text("Что-то пошло не так ...")
            self.error_window.show()

    def get_input_secretkey(self):
        try:
            text = self.plainTextEdit_5.toPlainText()
            secret_key = text.split(' ', 10)
            secret_key = [int(item) for item in secret_key]
            print(secret_key)
            return secret_key
        except:
            self.error_window.update_text("Неправильно введен секретный ключ")
            self.error_window.show()

    def get_input_number(self):
        try:
            text = self.plainTextEdit_4.toPlainText()
            text_list = list()
            buf_text = int(text)
            text_list.append(buf_text)
            print(text_list)
            return text_list
        except:
            self.error_window.update_text("Неправильно введено число")
            self.error_window.show()

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.error_window = BackpackAppError()
        self.success_window = BackpackAppSuccess()
        self.plainTextEdit_4.setPlaceholderText('числа, полученные после шифрования (num1 num2 ...)')
        self.plainTextEdit_5.setPlaceholderText('12 чисел через пробел (num_1 num2 ... num10 S N)')
        self.pushButton.clicked.connect(self.decrypt)


class BackpackAppError(QtWidgets.QMainWindow, ErrorWindowBackpack.Ui_MainWindow):
    def exit(self):
        self.close()

    def update_text(self, text):
        self.plainTextEdit_5.clear()
        self.plainTextEdit_5.appendPlainText(text)

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.plainTextEdit_5.setReadOnly(True)
        self.pushButton.clicked.connect(self.exit)


class BackpackAppPublicKey(QtWidgets.QMainWindow, PublicKeyWindowBackpack.Ui_MainWindow):
    def exit(self):
        self.close()

    def update_text(self, text):
        self.plainTextEdit_5.clear()
        self.plainTextEdit_5.appendPlainText(text)

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.plainTextEdit_5.setReadOnly(True)
        self.pushButton.clicked.connect(self.exit)


class BackpackAppSuccess(QtWidgets.QMainWindow, SuccessWindowBackpack.Ui_MainWindow):
    def exit(self):
        self.close()

    def update_text(self, text):
        self.plainTextEdit_5.clear()
        self.plainTextEdit_5.appendPlainText(text)

    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.plainTextEdit_5.setReadOnly(True)
        self.pushButton.clicked.connect(self.exit)


app = QtWidgets.QApplication(sys.argv)
app_main = BackpackAppMain()
app_main.show()
app.exec()

#7 12 24 51 95 195 387 772 1544 3088 private key
# 6211 N
# 13 S
#91 156 312 663 1235 2535 5031 3825 1439 2878 public key