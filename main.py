import sys
import os
import hashlib
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QLabel, QPushButton, QTextEdit, 
                           QLineEdit, QFileDialog, QMessageBox, QTabWidget,
                           QGroupBox, QFormLayout)
from PyQt6.QtCore import Qt
from tea import TinyEncryptionAlgorithmECB

class TEAApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.tea = TinyEncryptionAlgorithmECB()  # Создаем экземпляр алгоритма TEA
        self.init_ui()
        
    def init_ui(self):
        # Настройка основного окна
        self.setWindowTitle("TEA Шифрование/Дешифрование")
        self.setGeometry(100, 100, 800, 600)
        
        # Создание центрального виджета и макета
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Создание виджета вкладок
        tab_widget = QTabWidget()
        main_layout.addWidget(tab_widget)
        
        # Создание вкладок для работы с текстом и файлами
        text_tab = self.create_text_tab()
        file_tab = self.create_file_tab()
        
        tab_widget.addTab(text_tab, "Текст")
        tab_widget.addTab(file_tab, "Файлы")
        
    def create_text_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Группа для ввода ключа
        key_group = QGroupBox("Ключ шифрования")
        key_layout = QFormLayout()
        key_group.setLayout(key_layout)
        
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addRow("Введите ключ (минимум 16 символов):", self.key_input)
        
        # Добавление информационного текста
        key_info = QLabel("Ключ будет хешироваться с помощью SHA-256 для создания 16-байтного ключа")
        key_layout.addRow(key_info)
        
        layout.addWidget(key_group)
        
        # Группа для ввода и вывода текста
        text_group = QGroupBox("Текст")
        text_layout = QVBoxLayout()
        text_group.setLayout(text_layout)
        
        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Введите текст для шифрования/дешифрования...")
        text_layout.addWidget(QLabel("Исходный текст:"))
        text_layout.addWidget(self.input_text)
        
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setPlaceholderText("Результат будет отображен здесь...")
        text_layout.addWidget(QLabel("Результат:"))
        text_layout.addWidget(self.output_text)
        
        layout.addWidget(text_group)
        
        # Кнопки для шифрования/дешифрования
        buttons_layout = QHBoxLayout()
        
        encrypt_btn = QPushButton("Шифровать")
        encrypt_btn.clicked.connect(self.encrypt_text)
        buttons_layout.addWidget(encrypt_btn)
        
        decrypt_btn = QPushButton("Дешифровать")
        decrypt_btn.clicked.connect(self.decrypt_text)
        buttons_layout.addWidget(decrypt_btn)
        
        clear_btn = QPushButton("Очистить")
        clear_btn.clicked.connect(self.clear_text)
        buttons_layout.addWidget(clear_btn)
        
        save_btn = QPushButton("Сохранить результат")
        save_btn.clicked.connect(self.save_text_result)
        buttons_layout.addWidget(save_btn)
        
        layout.addLayout(buttons_layout)
        
        return widget
    
    def create_file_tab(self):
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Группа для ввода ключа
        key_group = QGroupBox("Ключ шифрования")
        key_layout = QFormLayout()
        key_group.setLayout(key_layout)
        
        self.file_key_input = QLineEdit()
        self.file_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        key_layout.addRow("Введите ключ (минимум 16 символов):", self.file_key_input)
        
        layout.addWidget(key_group)
        
        # Группа для выбора файлов
        file_group = QGroupBox("Файлы")
        file_layout = QVBoxLayout()
        file_group.setLayout(file_layout)
        
        input_file_layout = QHBoxLayout()
        self.input_file_path = QLineEdit()
        self.input_file_path.setReadOnly(True)
        input_file_layout.addWidget(QLabel("Входной файл:"))
        input_file_layout.addWidget(self.input_file_path)
        select_input_btn = QPushButton("Выбрать")
        select_input_btn.clicked.connect(self.select_input_file)
        input_file_layout.addWidget(select_input_btn)
        file_layout.addLayout(input_file_layout)
        
        output_file_layout = QHBoxLayout()
        self.output_file_path = QLineEdit()
        self.output_file_path.setReadOnly(True)
        output_file_layout.addWidget(QLabel("Выходной файл:"))
        output_file_layout.addWidget(self.output_file_path)
        select_output_btn = QPushButton("Выбрать")
        select_output_btn.clicked.connect(self.select_output_file)
        output_file_layout.addWidget(select_output_btn)
        file_layout.addLayout(output_file_layout)
        
        layout.addWidget(file_group)
        
        # Кнопки для шифрования/дешифрования файлов
        buttons_layout = QHBoxLayout()
        
        encrypt_file_btn = QPushButton("Шифровать файл")
        encrypt_file_btn.clicked.connect(self.encrypt_file)
        buttons_layout.addWidget(encrypt_file_btn)
        
        decrypt_file_btn = QPushButton("Дешифровать файл")
        decrypt_file_btn.clicked.connect(self.decrypt_file)
        buttons_layout.addWidget(decrypt_file_btn)
        
        layout.addLayout(buttons_layout)
        
        # Статус операции
        self.status_label = QLabel("Готов к работе")
        layout.addWidget(self.status_label)
        
        return widget
        
    def get_key(self, key_input):
        """Преобразование пользовательского ключа в 16-байтный ключ для TEA"""
        key_text = key_input.text()
        if not key_text:
            QMessageBox.warning(self, "Ошибка", "Ключ не может быть пустым!")
            return None
            
        # Используем SHA-256 для получения 32-байтного хэша, из которого берем первые 16 байт
        key_hash = hashlib.sha256(key_text.encode()).digest()[:16]
        return key_hash
        
    def encrypt_text(self):
        """Шифрование текста"""
        key = self.get_key(self.key_input)
        if not key:
            return
            
        input_data = self.input_text.toPlainText().encode()
        if not input_data:
            QMessageBox.warning(self, "Ошибка", "Введите текст для шифрования!")
            return
            
        try:
            encrypted_data = self.tea.encrypt(input_data, key)
            
            # Преобразуем бинарные данные в hex-строку для отображения
            hex_result = encrypted_data.hex()
            self.output_text.setText(hex_result)
            
        except Exception as e:
            QMessageBox.critical(self, "Ошибка шифрования", f"Произошла ошибка: {str(e)}")
            
    def decrypt_text(self):
        """Дешифрование текста"""
        key = self.get_key(self.key_input)
        if not key:
            return
            
        hex_input = self.input_text.toPlainText().strip()
        if not hex_input:
            QMessageBox.warning(self, "Ошибка", "Введите зашифрованный текст в HEX-формате!")
            return
            
        try:
            # Преобразуем hex-строку обратно в байты
            encrypted_data = bytes.fromhex(hex_input)
            decrypted_data = self.tea.decrypt(encrypted_data, key)
            
            # Пытаемся декодировать байты в строку
            try:
                result_text = decrypted_data.decode()
                self.output_text.setText(result_text)
            except UnicodeDecodeError:
                # Если декодирование не удалось, отображаем HEX
                self.output_text.setText(f"Ошибка декодирования Unicode. HEX: {decrypted_data.hex()}")
                
        except Exception as e:
            QMessageBox.critical(self, "Ошибка дешифрования", f"Произошла ошибка: {str(e)}")
            
    def clear_text(self):
        """Очистка полей ввода/вывода"""
        self.input_text.clear()
        self.output_text.clear()
        
    def save_text_result(self):
        """Сохранение результата в файл"""
        output_text = self.output_text.toPlainText()
        if not output_text:
            QMessageBox.warning(self, "Ошибка", "Нет данных для сохранения!")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Сохранить результат",
            "",
            "Текстовые файлы (*.txt);;Все файлы (*.*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(output_text)
                QMessageBox.information(self, "Успех", "Результат успешно сохранен!")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка сохранения", f"Произошла ошибка: {str(e)}")
                
    def select_input_file(self):
        """Выбор входного файла"""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Выберите входной файл",
            "",
            "Все файлы (*.*)"
        )
        
        if file_path:
            self.input_file_path.setText(file_path)
            
    def select_output_file(self):
        """Выбор выходного файла"""
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Выберите выходной файл",
            "",
            "Все файлы (*.*)"
        )
        
        if file_path:
            self.output_file_path.setText(file_path)
            
    def encrypt_file(self):
        """Шифрование файла"""
        key = self.get_key(self.file_key_input)
        if not key:
            return
            
        input_path = self.input_file_path.text()
        output_path = self.output_file_path.text()
        
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self, "Ошибка", "Выберите входной файл!")
            return
            
        if not output_path:
            QMessageBox.warning(self, "Ошибка", "Выберите выходной файл!")
            return
            
        try:
            # Чтение данных из входного файла
            with open(input_path, 'rb') as file:
                input_data = file.read()
                
            # Шифрование данных
            encrypted_data = self.tea.encrypt(input_data, key)
            
            # Запись зашифрованных данных в выходной файл
            with open(output_path, 'wb') as file:
                file.write(encrypted_data)
                
            self.status_label.setText("Файл успешно зашифрован!")
            QMessageBox.information(self, "Успех", "Файл успешно зашифрован!")
            
        except Exception as e:
            self.status_label.setText(f"Ошибка: {str(e)}")
            QMessageBox.critical(self, "Ошибка шифрования", f"Произошла ошибка: {str(e)}")
            
    def decrypt_file(self):
        """Дешифрование файла"""
        key = self.get_key(self.file_key_input)
        if not key:
            return
            
        input_path = self.input_file_path.text()
        output_path = self.output_file_path.text()
        
        if not input_path or not os.path.isfile(input_path):
            QMessageBox.warning(self, "Ошибка", "Выберите входной файл!")
            return
            
        if not output_path:
            QMessageBox.warning(self, "Ошибка", "Выберите выходной файл!")
            return
            
        try:
            # Чтение данных из входного файла
            with open(input_path, 'rb') as file:
                encrypted_data = file.read()
                
            # Дешифрование данных
            decrypted_data = self.tea.decrypt(encrypted_data, key)
            
            # Запись расшифрованных данных в выходной файл
            with open(output_path, 'wb') as file:
                file.write(decrypted_data)
                
            self.status_label.setText("Файл успешно дешифрован!")
            QMessageBox.information(self, "Успех", "Файл успешно дешифрован!")
            
        except Exception as e:
            self.status_label.setText(f"Ошибка: {str(e)}")
            QMessageBox.critical(self, "Ошибка дешифрования", f"Произошла ошибка: {str(e)}")


def main():
    app = QApplication(sys.argv)
    window = TEAApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
