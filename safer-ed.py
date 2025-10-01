# -*- coding: utf-8 -*-
import math as m
import hashlib
import sys
from mainwindow import Ui_MainWindow
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtCore import QObject, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog
)
import os
import datetime


class safer_cipher(QThread):
    finished = pyqtSignal()
    progress = pyqtSignal(int,int)

    def __init__(self, parent, filename, key_txt, em, direction):
        super(safer_cipher, self).__init__(parent)
        # Имя файла
        self.filename = filename
        # Ключ в текстовом виде
        self.key_txt = key_txt
        # Режим шифрования/дешифрования (ECB,CBC,CFB,OFB)
        self.em = em  
        # Направление - шифрование или дешифрование
        self.direction = direction

# Таблица 45 в степени х mod 257
        self.expf = [1, 45, 226, 147, 190, 69, 21, 174, 
                       120, 3, 135, 164, 184, 56, 207, 63, 8, 103, 9, 148, 235, 38, 168, 107, 
                       189, 24, 52, 27, 187, 191, 114, 247, 64, 53, 72, 156, 81, 47, 59, 85, 
                       227, 192, 159, 216, 211, 243, 141, 177, 
                       255, 167, 62, 220, 134, 119, 215, 166, 17, 251, 244, 186, 146, 145, 100, 131,
                       241, 51, 239, 218, 44, 181, 178, 43,
                       136, 209, 153, 203, 140, 132, 29, 20, 
                       129, 151, 113, 202, 95, 163, 139, 87, 60, 130, 196, 82, 92, 28, 232, 160, 4, 180, 133, 74, 246, 19, 84, 182, 
                       223, 12, 26, 142, 222, 224, 57, 252, 32, 155, 36, 78, 169, 152, 158, 171,
                       242, 96, 208, 108, 234, 250, 199, 217, 0, 212, 31, 110, 67, 188, 236, 83,
                       137, 254, 122, 93, 73, 201, 50, 194, 
                       249, 154, 248, 109, 22, 219, 89, 150, 68, 233, 205, 230, 70, 66, 143, 10, 
                       193, 204, 185, 101, 176, 210, 198, 172, 30, 65, 98, 41, 46, 14, 116, 80, 2, 90, 195, 37, 123, 138, 42, 91,
                       240, 6, 13, 71, 111, 112, 157, 126, 16, 206, 18, 39, 213, 76, 79, 214,
                       121, 48, 104, 54, 117, 125, 228, 237, 
                       128, 106, 144, 55, 162, 94, 118, 170, 
                       197, 127, 61, 175, 165, 229, 25, 97, 
                       253, 77, 124, 183, 11, 238, 173, 75, 34, 245, 231, 115, 35, 33, 200, 5, 
                       225, 102, 221, 179, 88, 105, 99, 86, 15, 161, 49, 149, 23, 7, 58, 40
                      ]

# Таблица log45(x)
        self.logf = [128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173, 248,
                         192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168, 130, 
                         112, 237, 232, 236, 114, 179, 21, 195,
                         255, 171, 182, 71, 68, 1, 172, 37, 
                         201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50, 15, 32, 169, 
                         157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225, 115, 198, 
                         175, 36, 91, 135, 102, 39, 247, 87, 
                         244, 150, 177, 183, 92, 139, 213, 84, 
                         121, 223, 170, 246, 62, 163, 241, 17, 202, 
                         245, 209, 23, 123, 147, 131, 188, 189, 82, 30, 235, 174, 
                         204, 214, 53, 8, 200, 138, 180, 226, 205, 191, 217, 208, 80, 89, 63,
                         77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107, 158, 210, 61, 
                         60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118, 42, 95, 249, 
                         212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7, 219, 
                         164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4, 29, 41, 160, 143, 178, 90, 216, 166, 126, 
                         238, 141, 83, 75, 161, 154, 193, 14, 
                         122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242, 108, 104, 
                         109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207, 229, 66, 
                         184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224, 137, 48]

    def run(self):
        self.input_data = self.readDataFromFile(self.filename)
        self.lst_key = self.gen_key(self.key_txt)
        if self.direction:
            self.transformed_data=self.encrypt_data(self.input_data, self.lst_key, self.em)
        else:
            self.transformed_data=self.decrypt_data(self.input_data, self.lst_key, self.em)
        self.writeDataToFile(self.filename+".out",self.transformed_data)
        self.finished.emit()

    # Пишем данные в файл
    def writeDataToFile(self, filename, data):
        data_txt = data.to_bytes((data.bit_length()+7)//8, byteorder="big")
        with open(filename,"wb") as handle:
            handle.write(data_txt)

    # Читаем данные из файла
    def readDataFromFile(self, filename):
        with open(filename, 'rb') as handle:
            data = bytes(handle.read())
            data_int = int.from_bytes(data, byteorder='big')
            return data_int

    def split64(self, data):
        s64count = int(m.ceil(data.bit_length()/64))
        splits=[]
        for i in range (0, s64count):
            splits.append(data&((1<<64)-1))
            data = data>>64
        return splits

    def gen_key(self, key):
        key_lst = []
        key = key.encode('ascii')
        key_lst.insert(0, int.from_bytes(key, byteorder='big'))
        for i in range(2, 14):
            a = 0
            for j in range (0, 8):
                exp1=self.expf[(9*i+j)%256]
                exp2=self.expf[exp1]%256
                a=(a<<8)|((key[j]<<3)+exp2)
            key_lst.append(a)
        return key_lst

    # Процедура шифрования блока, на ходе блок и ключ в виде списка
    def encrypt(self, block, key_lst):
        # Выполняем операцию шифрования в 6 раундов
        for j in range (0, 6):
            # Подготавливаем ключи для раунда
            round_key1 = key_lst[2*j]
            round_key2 = key_lst[2*j+1]
            bit_key1 = []
            bit_key2 = []
            for k in range (0, 8):
                bit_key1.insert(0,round_key1&0xff)
                round_key1 = round_key1>>8
            for k in range (0, 8):
                bit_key2.insert(0,round_key2&0xff)
                round_key2 = round_key2>>8

            # XOR шифруемого блока с первой частью ключа (части 1,4,5,8)
            block[0] = block[0]^bit_key1[0]
            block[3] = block[3]^bit_key1[3]
            block[4] = block[4]^bit_key1[4]
            block[7] = block[7]^bit_key1[7]
            # Складываем шифруемый блок с первой частью ключа по модулю 256(части 2,3,6,7)
            block[1] = (block[1]+bit_key1[1])%256
            block[2] = (block[2]+bit_key1[2])%256
            block[5] = (block[5]+bit_key1[5])%256
            block[6] = (block[6]+bit_key1[6])%256

            # Производим нелинейное преобразование шифруемого блока использую операцию 45 в степени Х по модулю 257 (части 1,4,5,8), 
            block[0] = self.expf[block[0]]
            block[3] = self.expf[block[3]]
            block[4] = self.expf[block[4]]
            block[7] = self.expf[block[7]]
            # Производим нелинейное преобразование шифруемого блока использую операцию log45(X) (части 2,3,6,7), 
            block[1] = self.logf[block[1]]
            block[2] = self.logf[block[2]]
            block[5] = self.logf[block[5]]
            block[6] = self.logf[block[6]]

            # Складываем шифруемый блок со второй частью ключа по модулю 256 (части 1,4,5,8)
            block[0] = (block[0]+bit_key2[0])%256
            block[3] = (block[3]+bit_key2[3])%256
            block[4] = (block[4]+bit_key2[4])%256
            block[7] = (block[7]+bit_key2[7])%256
            # XOR шифруемого блока со второй частью ключа (части 2,3,6,7)
            block[1] = block[1]^bit_key2[1]
            block[2] = block[2]^bit_key2[2]
            block[5] = block[5]^bit_key2[5]
            block[6] = block[6]^bit_key2[6]

            #Применяем псевдопреобразование Адамара
            bit_keya = [0,0,0,0,0,0,0,0]
            bit_keya[0] = (2*block[0]+block[1])%256
            bit_keya[1] = (block[0]+block[1])%256
            bit_keya[2] = (2*block[2]+block[3])%256
            bit_keya[3] = (block[2]+block[3])%256
            bit_keya[4] = (2*block[4]+block[5])%256
            bit_keya[5] = (block[4]+block[5])%256
            bit_keya[6] = (2*block[6]+block[7])%256
            bit_keya[7] = (block[6]+block[7])%256
            
            block[0] = bit_keya[0]
            block[3] = bit_keya[3]
            block[4] = bit_keya[4]
            block[7] = bit_keya[7]
            block[1] = bit_keya[1]
            block[2] = bit_keya[2]
            block[5] = bit_keya[5]
            block[6] = bit_keya[6]

        # Берем последний подключ
        last_key = key_lst[12]
        bit_lastkey =[]

        for k in range (0, 8):
            bit_lastkey.insert(0,last_key&0xff)
            last_key = last_key>>8
        # И прогоняем еще раз с ним операцию XOR и сложения
        # XOR шифруемого блока с первой частью ключа (части 1,4,5,8)
        block[0] = block[0]^bit_lastkey[0]
        block[3] = block[3]^bit_lastkey[3]
        block[4] = block[4]^bit_lastkey[4]
        block[7] = block[7]^bit_lastkey[7]
        # Складываем шифруемый блок с первой частью ключа по модулю 256(части 2,3,6,7)
        block[1] = (block[1]+bit_lastkey[1])%256
        block[2] = (block[2]+bit_lastkey[2])%256
        block[5] = (block[5]+bit_lastkey[5])%256
        block[6] = (block[6]+bit_lastkey[6])%256

        return block

    # Процедура дешифрования блока, на ходе блок и ключ в виде списка
    def decrypt(self, block, key_lst):
        # Берем последний подключ
        bit_lastkey = []
        last_key = key_lst[12]
        for k in range (0, 8):
            bit_lastkey.insert(0,last_key&0xff)
            last_key = last_key>>8
        # Вычитаем шифруемый блок с первой частью ключа по модулю 256(части 2,3,6,7)
        block[1] = (block[1]-bit_lastkey[1])%256
        block[2] = (block[2]-bit_lastkey[2])%256
        block[5] = (block[5]-bit_lastkey[5])%256
        block[6] = (block[6]-bit_lastkey[6])%256
        # XOR шифруемого блока с первой частью ключа (части 1,4,5,8)
        block[0] = block[0]^bit_lastkey[0]
        block[3] = block[3]^bit_lastkey[3]
        block[4] = block[4]^bit_lastkey[4]
        block[7] = block[7]^bit_lastkey[7]

        # Выполняем операцию шифрования в 6 раундов
        for j in range (0, 6):
            # Подготавливаем ключи для раунда
            round_key2 = key_lst[11-2*j]
            round_key1 = key_lst[10-2*j]
            bit_key1 = []
            bit_key2 = []
            for k in range (0, 8):
                bit_key1.insert(0,round_key1&0xff)
                round_key1 = round_key1>>8
            for k in range (0, 8):
                bit_key2.insert(0,round_key2&0xff)
                round_key2 = round_key2>>8

            #Применяем обратное псевдопреобразование Адамара
            bit_keya = [0,0,0,0,0,0,0,0]

            bit_keya[0] = (block[0]-block[1])%256
            bit_keya[1] = (-block[0]+2*block[1])%256
            bit_keya[2] = (block[2]-block[3])%256
            bit_keya[3] = (-block[2]+2*block[3])%256
            bit_keya[4] = (block[4]-block[5])%256
            bit_keya[5] = (-block[4]+2*block[5])%256
            bit_keya[6] = (block[6]-block[7])%256
            bit_keya[7] = (-block[6]+2*block[7])%256

            block[0] = bit_keya[0]
            block[3] = bit_keya[3]
            block[4] = bit_keya[4]
            block[7] = bit_keya[7]
            block[1] = bit_keya[1]
            block[2] = bit_keya[2]
            block[5] = bit_keya[5]
            block[6] = bit_keya[6]

            # XOR шифруемого блока со второй частью ключа (части 2,3,6,7)
            block[1] = block[1]^bit_key2[1]
            block[2] = block[2]^bit_key2[2]
            block[5] = block[5]^bit_key2[5]
            block[6] = block[6]^bit_key2[6]
            # Складываем шифруемый блок со второй частью ключа по модулю 256 (части 1,4,5,8)
            block[0] = (block[0]-bit_key2[0])%256
            block[3] = (block[3]-bit_key2[3])%256
            block[4] = (block[4]-bit_key2[4])%256
            block[7] = (block[7]-bit_key2[7])%256

            # Производим нелинейное преобразование шифруемого блока использую операцию 45 в степени Х по модулю 257 (части 2,3,6,7), 
            block[1] = self.expf[block[1]]
            block[2] = self.expf[block[2]]
            block[5] = self.expf[block[5]]
            block[6] = self.expf[block[6]]
            # Производим нелинейное преобразование шифруемого блока использую операцию log45(X) (части 1,4,5,8), 
            block[0] = self.logf[block[0]]
            block[3] = self.logf[block[3]]
            block[4] = self.logf[block[4]]
            block[7] = self.logf[block[7]]

            # Складываем шифруемый блок с первой частью ключа по модулю 256(части 2,3,6,7)
            block[1] = (block[1]-bit_key1[1])%256
            block[2] = (block[2]-bit_key1[2])%256
            block[5] = (block[5]-bit_key1[5])%256
            block[6] = (block[6]-bit_key1[6])%256
            # XOR шифруемого блока с первой частью ключа (части 1,4,5,8)
            block[0] = block[0]^ bit_key1[0]
            block[3] = block[3]^ bit_key1[3]
            block[4] = block[4]^ bit_key1[4]
            block[7] = block[7]^ bit_key1[7]

        return(block)

    def encrypt_data(self, data, key_lst, em):
        data_split = self.split64(data)
        filesize=(len(data_split)-1)*64
        text_enc = []
        cbc_vector = b"XLa.957u"
        cbc_vector = int.from_bytes(cbc_vector, byteorder='big')

        if em == 'ECB':
            for i in range (0, len(data_split)):
                round_word = data_split[i]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                self.progress.emit(i*64,filesize)
        
        if em == "CBC":
            for i in range (0, len(data_split)):
                if i == 0:
                    round_word = data_split[i]^cbc_vector
                else:
                    round_word = data_split[i]^text_enc[i-1]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                self.progress.emit(i*64,filesize)

        if em == "CFB":
            for i in range (0, len(data_split)):
                if i == 0:
                    round_word = cbc_vector
                else:
                    round_word = text_enc[i-1]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                text_enc[i]=data_split[i]^text_enc[i]
                self.progress.emit(i*64,filesize)

        if em == 'OFB':
            for i in range (0, len(data_split)):
                if i == 0:
                    round_word = cbc_vector
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                round_word = data_split_enc[0]
                for k in range (1, 8):
                    round_word = (round_word<<8)|data_split_enc[k]
                text_enc.append(data_split[i]^round_word)
                self.progress.emit(i*64,filesize)

        result = text_enc[len(text_enc)-1]
        for i in range (0, len(text_enc)-1):
            result = (result<<64)|text_enc[len(text_enc)-2-i]
        return(result)

    def decrypt_data(self, data, key_lst, em):
        cbc_vector = b"XLa.957u"
        cbc_vector = int.from_bytes(cbc_vector, byteorder='big')
        data_split = self.split64(data)
        filesize=(len(data_split)-1)*64
        text_enc = []

        if em == "ECB":
            for i in range (0, len(data_split)):
                round_word = data_split[i]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.decrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                self.progress.emit(i*64,filesize)

        if em == "CBC":
            for i in range (0, len(data_split)):
                round_word = data_split[i]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.decrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                if i == 0:
                    text_enc[i] = text_enc[i]^cbc_vector
                else:
                    text_enc[i] = text_enc[i]^data_split[i-1]
                self.progress.emit(i*64,filesize)

        if em == "CFB":
            for i in range (0, len(data_split)):
                if i == 0:
                    round_word = cbc_vector
                else:
                    round_word = data_split[i-1]
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                text_enc.append(data_split_enc[0])
                for k in range (1, 8):
                    text_enc[i] = (text_enc[i]<<8)|data_split_enc[k]
                text_enc[i]=data_split[i]^text_enc[i]
                self.progress.emit(i*64,filesize)

        if em == 'OFB':
            for i in range (0, len(data_split)):
                if i == 0:
                    round_word = cbc_vector
                data_split_enc = []
                for k in range (0, 8):
                    data_split_enc.insert(0,round_word&0xff)
                    round_word = round_word>>8
                data_split_enc = self.encrypt(data_split_enc, key_lst)
                round_word = data_split_enc[0]
                for k in range (1, 8):
                    round_word = (round_word<<8)|data_split_enc[k]
                text_enc.append(data_split[i]^round_word)
                self.progress.emit(i*64,filesize)

        result = text_enc[len(text_enc)-1]
        for i in range (0, len(text_enc)-1):
            result = (result<<64)|text_enc[len(text_enc)-2-i]
        return(result)

# Главный класс приложения, чтобы вызвать окно
class Window(QMainWindow, Ui_MainWindow):
    thread=0
# Инициализируем наше главное окно, прописываем в нем все что нужно
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setupUi(self)
        self.connectSignalsSlots()
# Связываем сигналы от меню, с вызовами функций
    def connectSignalsSlots(self):
        self.actionOpen.triggered.connect(self.openFileDialog)
        self.actionEncrypt.triggered.connect(self.startEncrypt)
        self.actionDecrypt.triggered.connect(self.startDecrypt)
# Метод для вызова диалога выбора файла, если файл был выбран, то прописываем его имя в текстовое поле
# и включаем в меню возможность выбора Encrypt/Decrypt (по умолчанию они у нас выключены)
    def openFileDialog(self):
        options = QFileDialog.Options()
        options |= QFileDialog.DontUseNativeDialog
        fileName, _ = QFileDialog.getOpenFileName(self,"Please select file", "","All Files (*)", options=options)
        if fileName:
            self.fileNameInput.setText(fileName)
            self.actionEncrypt.setEnabled(True)
            self.actionDecrypt.setEnabled(True)
    # Запускаем шифрование
    def startEncrypt(self):
        self.thread = QThread()
        self.worker = safer_cipher(self, self.fileNameInput.text(), hashlib.sha256(self.keyInput.text().encode("ascii")).hexdigest()[:8], self.opModeInput.currentText(), True)
        # Step 5: Connect signals and slots
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.updateProgress)
        self.worker.finished.connect(self.on_finished)
        self.actionEncrypt.setEnabled(False)
        self.actionDecrypt.setEnabled(False)
        self.actionOpen.setEnabled(False)
        # Step 6: Start the thread
        self.thread.start()
    # Запускаем дешифрование
    def startDecrypt(self):
        self.thread = QThread()
        self.worker = safer_cipher(self, self.fileNameInput.text(), hashlib.sha256(self.keyInput.text().encode("ascii")).hexdigest()[:8] , self.opModeInput.currentText(), False)
        # Step 5: Connect signals and slots
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.updateProgress)
        self.worker.finished.connect(self.on_finished)
        self.actionEncrypt.setEnabled(False)
        self.actionDecrypt.setEnabled(False)
        self.actionOpen.setEnabled(False)
        # Step 6: Start the thread
        self.thread.start()
    @QtCore.pyqtSlot()
    def on_finished(self):
        self.actionEncrypt.setEnabled(True)
        self.actionDecrypt.setEnabled(True)
        self.actionOpen.setEnabled(True)
        self.progressBar.setFormat("Completed")
        self.thread.terminate()
    @QtCore.pyqtSlot(int,int)
    def updateProgress(self,i,i1):
        self.progressBar.setMaximum(i1)
        self.progressBar.setProperty("value", i)
        self.progressBar.setTextVisible(True)
        self.progressBar.setFormat("%v of %m bytes")



# Код программы вызываемый при старте, запускает наше окно
if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = Window()
    win.show()
    sys.exit(app.exec())
