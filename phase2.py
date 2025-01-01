# -*- coding: utf-8 -*-
from PyQt5 import QtCore, QtGui, QtWidgets
from crypto.AsymmetricCipher import RSA
from crypto.SymmetricCipher import AESEncryption, DESEncryption, Encryptor

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        # Global styles
        MAIN_BG_COLOR = "#f5f5f5"
        LABEL_COLOR = "#333333"
        BUTTON_PRIMARY = """
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:disabled {
                background-color: #cccccc;
                color: #666666;
            }
        """

        LIST_WIDGET_STYLE = """
            QListWidget {
                background-color: white;
                border: 1px solid #dcdcdc;
                border-radius: 4px;
                padding: 5px;
            }
            QListWidget::item {
                padding: 5px;
                border-radius: 2px;
            }
            QListWidget::item:selected {
                background-color: #4CAF50;
                color: white;
            }
            QListWidget::item:hover {
                background-color: #e6e6e6;
            }
        """

        INPUT_STYLE = """
            QLineEdit {
                background-color: white;
                border: 1px solid #dcdcdc;
                border-radius: 4px;
                padding: 5px;
                color: #333333;
            }
            QLineEdit:focus {
                border: 1px solid #4CAF50;
            }
        """

        # Main Window Setup
        MainWindow.setObjectName("Secure Communication Suite")
        MainWindow.resize(1103, 720)
        MainWindow.setStyleSheet(f"background-color: {MAIN_BG_COLOR};")

        # Central Widget
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.centralwidget.setStyleSheet(f"background-color: {MAIN_BG_COLOR};")

        # Algorithm Label
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(730, 50, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        self.label_3.setFont(font)
        self.label_3.setStyleSheet(f"color: {LABEL_COLOR}; font-weight: bold;")
        self.label_3.setObjectName("label_3")
        self.label_3.setText("Algorithm")

        # Vertical Layout for Labels
        self.verticalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(50, 60, 183, 311))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")

        # Labels
        labels = ["Input text:", "Cipher text:", "Plain text (Decryption)", "Digital signature status"]
        self.labels = []
        for text in labels:
            label = QtWidgets.QLabel(self.verticalLayoutWidget)
            font = QtGui.QFont()
            font.setFamily("Times New Roman")
            font.setPointSize(12)
            label.setFont(font)
            label.setStyleSheet(f"color: {LABEL_COLOR}; font-weight: bold;")
            label.setText(text)
            self.verticalLayout.addWidget(label)
            self.labels.append(label)

        # List Widget
        self.listWidget = QtWidgets.QListWidget(self.centralwidget)
        self.listWidget.setGeometry(QtCore.QRect(830, 50, 256, 192))
        font = QtGui.QFont()
        font.setFamily("Times New Roman")
        font.setPointSize(12)
        self.listWidget.setFont(font)
        self.listWidget.setStyleSheet(LIST_WIDGET_STYLE)
        self.listWidget.setObjectName("listWidget")

        # Add items to list widget
        algorithms = ["DES", "AES-128", "AES-192", "AES-256", "RSA"]
        for algo in algorithms:
            item = QtWidgets.QListWidgetItem(algo)
            self.listWidget.addItem(item)

        # Input and Output Fields
        self.inputText = QtWidgets.QLineEdit(self.centralwidget)
        self.inputText.setGeometry(QtCore.QRect(250, 60, 400, 30))
        self.inputText.setStyleSheet(INPUT_STYLE)

        # Result Labels
        label_style = """
            QLabel {
                background-color: white;
                border: 1px solid #dcdcdc;
                border-radius: 4px;
                padding: 5px;
                color: #333333;
            }
        """

        self.cipherTextLabel = QtWidgets.QLabel(self.centralwidget)
        self.cipherTextLabel.setStyleSheet(label_style)
        self.cipherTextLabel.setGeometry(QtCore.QRect(250, 120, 400, 30))

        self.decryptionTextLabel = QtWidgets.QLabel(self.centralwidget)
        self.decryptionTextLabel.setStyleSheet(label_style)
        self.decryptionTextLabel.setGeometry(QtCore.QRect(250, 180, 400, 30))

        self.digitalSignatureVerificationLabel = QtWidgets.QLabel(self.centralwidget)
        self.digitalSignatureVerificationLabel.setStyleSheet(label_style)
        self.digitalSignatureVerificationLabel.setGeometry(QtCore.QRect(250, 240, 400, 30))

        # Buttons Layout
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.centralwidget)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(180, 440, 701, 80))
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.horizontalLayout.setContentsMargins(0, 0, 0, 0)

        # Buttons
        buttons = [
            ("encryptButton", "Encrypt"),
            ("decryptButton", "Decrypt"),
            ("digitalSignatureButton", "Digital Signature"),
            ("verifyButton", "Verify Signature")
        ]

        for btn_name, btn_text in buttons:
            button = QtWidgets.QPushButton(self.horizontalLayoutWidget)
            button.setStyleSheet(BUTTON_PRIMARY)
            button.setText(btn_text)
            button.setEnabled(False)
            font = QtGui.QFont()
            font.setFamily("Times New Roman")
            font.setPointSize(12)
            button.setFont(font)
            button.setObjectName(btn_name)
            self.horizontalLayout.addWidget(button)
            setattr(self, btn_name, button)

        MainWindow.setCentralWidget(self.centralwidget)

        # Connect signals
        self.listWidget.itemClicked.connect(self.on_item_clicked)
        self.encryptButton.clicked.connect(self.on_encryption_clicked)
        self.decryptButton.clicked.connect(self.on_decryption_clicked)
        self.digitalSignatureButton.clicked.connect(self.on_generate_digital_signature_clicked)
        self.verifyButton.clicked.connect(self.on_validate_clicked)

    def on_item_clicked(self, item):
        self.encryptionAlgorithm = item.text()
        self.encryptButton.setEnabled(True)
        if self.encryptionAlgorithm == "RSA":
            self.digitalSignatureButton.setEnabled(True)
            self.verifyButton.setEnabled(True)
        else:
            self.digitalSignatureButton.setEnabled(False)
            self.verifyButton.setEnabled(False)

    def on_encryption_clicked(self):
        self.plaintext = self.inputText.text().encode()
        if self.encryptionAlgorithm == "DES":
            des_worker = DESEncryption()
            self.encryptor = Encryptor(des_worker)
            self.key = des_worker.generate_key()
            self.iv = des_worker.generate_iv()
            self.cipherText = self.encryptor.encrypt_text(self.plaintext, self.key, self.iv)
        elif self.encryptionAlgorithm.startswith("AES"):
            key_size = int(self.encryptionAlgorithm.split("-")[1]) // 8
            aes_worker = AESEncryption()
            self.encryptor = Encryptor(aes_worker)
            self.key = aes_worker.generate_key(key_size)
            self.iv = aes_worker.generate_iv()
            self.cipherText = self.encryptor.encrypt_text(self.plaintext, self.key, self.iv)
        elif self.encryptionAlgorithm == "RSA":
            self.rsa_worker = RSA()
            self.public_key, self.private_key = self.rsa_worker.generate_key_pair()
            self.cipherText = self.rsa_worker.encrypt(self.plaintext, self.public_key)

        self.cipherTextLabel.setText(self.cipherText.decode('latin-1'))
        self.decryptButton.setEnabled(True)

    def on_decryption_clicked(self):
        if self.encryptionAlgorithm == "RSA":
            self.decrypted_plaintext = self.rsa_worker.decrypt(self.cipherText, self.private_key)
        else:
            self.decrypted_plaintext = self.encryptor.decrypt_text(self.cipherText, self.key, self.iv)
        self.decryptionTextLabel.setText(self.decrypted_plaintext.decode('latin-1'))

    def on_generate_digital_signature_clicked(self):
        self.digitalSignature = self.rsa_worker.generate_digital_signature(self.plaintext, self.private_key)
        self.digitalSignatureVerificationLabel.setText("Signature Generated")

    def on_validate_clicked(self):
        if self.rsa_worker.verify_digital_signature(self.plaintext, self.digitalSignature, self.public_key):
            self.digitalSignatureVerificationLabel.setText("Verified")
        else:
            self.digitalSignatureVerificationLabel.setText("Rejected")

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())