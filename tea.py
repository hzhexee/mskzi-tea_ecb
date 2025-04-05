import struct
import logging

from hashlib import sha256
from argparse import ArgumentParser
from ctypes import c_uint32


### Магические константы
ROUNDS = 32  # Количество раундов
BLOCK_BYTE_SIZE = 8  # Размер блока в байтах
BLOCK_UINT32_SIZE = 2  # Размер блока в uint32
KEY_BYTE_SIZE = 16  # Размер ключа в байтах
KEY_UINT32_SIZE = 4  # Размер ключа в uint32
LOGGER = logging.getLogger(__name__)


#
#  Вспомогательные функции для математики с c_uint32
#
def lshift4(a):
    """ Сдвиг влево на 4 позиции """
    return c_uint32(a << 4).value

def rshift5(a):
    """ Сдвиг вправо на 5 позиций """
    return c_uint32(a >> 5).value

def lshift4_add(a, b):
    """ Сдвиг влево на 4 позиции и сложение с b """
    result = lshift4(a) + c_uint32(b).value
    return c_uint32(result).value

def rshift5_add(a, b):
    """ Сдвиг вправо на 5 позиций и сложение с b """
    result = rshift5(a) + c_uint32(b).value
    return c_uint32(result).value

def add(a, b):
    """ Сложение a и b """
    result = c_uint32(a).value + c_uint32(b).value
    return c_uint32(result).value

def sub(a, b):
    """ Вычитание b из a """
    result = c_uint32(a).value - c_uint32(b).value
    return c_uint32(result).value

def xor(a, b, c):
    """ Операция XOR для a, b и c """
    middle = c_uint32(a).value ^ c_uint32(b).value
    return c_uint32(middle ^ c_uint32(c).value).value


class TinyEncryptionAlgorithmECB(object):
    """ 
    Класс реализации алгоритма шифрования TEA с режимом ECB (Electronic CodeBook)
    
    В режиме ECB каждый блок данных шифруется независимо от других блоков.
    Одинаковые блоки открытого текста всегда шифруются в одинаковые блоки шифротекста 
    при использовании одного и того же ключа.
    """

    def __init__(self, delta=0x9e3779b9, summation=0xc6ef3720):
        self.delta = c_uint32(delta).value
        self.summation = c_uint32(summation).value

    def encrypt_block(self, block, key):
        """
        Шифрование одного 64-битного блока с использованием заданного ключа
        @param block: список из двух элементов типа c_uint32
        @param key: список из четырех элементов типа c_uint32
        """
        assert len(block) == BLOCK_UINT32_SIZE
        assert len(key) == KEY_UINT32_SIZE
        sumation = 0
        delta = self.delta
        for _ in range(0, ROUNDS):
            sumation = c_uint32(sumation + delta).value
            block[0] = add(
                block[0],
                xor(
                    lshift4_add(block[1], key[0]),
                    add(block[1], sumation),
                    rshift5_add(block[1], key[1])
                )
            )
            block[1] = add(
                block[1],
                xor(
                    lshift4_add(block[0], key[2]),
                    add(block[0], sumation),
                    rshift5_add(block[0], key[3])
                )
            )
        return block


    def decrypt_block(self, block, key):
        """
        Расшифрование одного 64-битного блока с использованием заданного ключа
        @param block: список из двух элементов типа c_uint32
        @param key: список из четырех элементов типа c_uint32
        """
        assert len(block) == BLOCK_UINT32_SIZE
        assert len(key) == KEY_UINT32_SIZE
        sumation = self.summation
        delta = self.delta
        for _ in range(0, ROUNDS):
            block[1] = sub(
                block[1],
                xor(
                    lshift4_add(block[0], key[2]),
                    add(block[0], sumation),
                    rshift5_add(block[0], key[3])
                )
            )
            block[0] = sub(
                block[0],
                xor(
                    lshift4_add(block[1], key[0]),
                    add(block[1], sumation),
                    rshift5_add(block[1], key[1])
                )
            )
            sumation = c_uint32(sumation - delta).value
        return block

    def get_padded_plaintext(self, data):
        """ Добавление заполнения к открытому тексту, размер блока 64 бита (8 байт) """
        data = bytearray(data)
        if len(data) % 8 == 0:
            data += bytearray([8] * 8)  # Заполнение байтом со значением 8
        else:
            pad = 8 - (len(data) % 8)
            data += bytearray([pad] * pad)  # Создаем массив байтов с нужным значением
        return data

    def remove_padding(self, data):
        """ Удаление заполнения из расшифрованного текста """
        # Преобразование последнего байта в целое число
        pad = data[-1]
        assert 1 <= pad <= 8
        if not all([byte == data[-1] for byte in data[pad * -1:]]):
            raise ValueError('Некорректное заполнение')
        return data[:pad * -1]

    def encrypt(self, data, key):
        """
        Шифрование данных `data` с помощью ключа `key` в режиме ECB
        
        В режиме ECB каждый 64-битный блок шифруется независимо от других.
        
        @param data: данные для шифрования
        @param key: 16-байтный ключ шифрования
        @return: зашифрованные данные в виде bytearray
        """
        plaintext_buffer = self.get_padded_plaintext(data)
        key_buffer = bytearray(key)
        assert len(key_buffer) == KEY_BYTE_SIZE
        assert len(plaintext_buffer) % 8 == 0
        key = [
            # Это байтовые индексы (0 - 16)
            # struct.unpack возвращает кортеж, поэтому используем [0]
            c_uint32(struct.unpack("I", key_buffer[:4])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[4:8])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[8:12])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[12:])[0]).value
        ]
        # Итерация по буферу с шагом 8 байт (режим ECB - каждый блок шифруется независимо)
        ciphertext = bytearray()
        for index in range(0, len(plaintext_buffer), 8):
            block = [
                c_uint32(struct.unpack("I", plaintext_buffer[index:index + 4])[0]).value,
                c_uint32(struct.unpack("I", plaintext_buffer[index + 4:index + 8])[0]).value
            ]
            block = self.encrypt_block(block, key)
            ciphertext += struct.pack("I", block[0])
            ciphertext += struct.pack("I", block[1])
        return ciphertext

    def decrypt(self, data, key):
        """
        Расшифрование данных `data` с помощью ключа `key` в режиме ECB
        
        В режиме ECB каждый 64-битный блок расшифровывается независимо от других.
        
        @param data: зашифрованные данные
        @param key: 16-байтный ключ шифрования
        @return: расшифрованные данные в виде bytearray
        """
        ciphertext_buffer = bytearray(data)
        key_buffer = bytearray(key)
        assert len(key_buffer) == KEY_BYTE_SIZE
        assert len(ciphertext_buffer) % 8 == 0
        key = [
            c_uint32(struct.unpack("I", key_buffer[:4])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[4:8])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[8:12])[0]).value,
            c_uint32(struct.unpack("I", key_buffer[12:])[0]).value
        ]
        # Итерация по буферу с шагом 8 байт (режим ECB - каждый блок расшифровывается независимо)
        plaintext = bytearray()
        for index in range(0, len(ciphertext_buffer), 8):
            block = [
                c_uint32(struct.unpack("I", ciphertext_buffer[index:index + 4])[0]).value,
                c_uint32(struct.unpack("I", ciphertext_buffer[index + 4:index + 8])[0]).value
            ]
            block = self.decrypt_block(block, key)
            plaintext += struct.pack("I", block[0])
            plaintext += struct.pack("I", block[1])
        return self.remove_padding(plaintext)

# Для обратной совместимости
TinyEncryptionAlgorithm = TinyEncryptionAlgorithmECB
