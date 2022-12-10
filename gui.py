
import sys
import password_checker

from ghidra_script import (buf_overflow_checker, int_overflow_checker, sys_call_checker,endless_recursive_call_checker)
from PyQt5.QtWidgets import ( QApplication, QMainWindow,QVBoxLayout, QHBoxLayout,
                              QFontDialog,QDesktopWidget, QAction, QFileDialog,
                              QTextBrowser, QPushButton, QWidget,
                              QMessageBox)
from PyQt5.QtGui import QIcon



class MyApp(QMainWindow):

    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        #self.textEdit = QTextEdit()
        #self.setCentralWidget(self.textEdit)
        #self.statusBar()

        self.dir_path = ""
        self.file_path = ""

        self.tb = QTextBrowser()
        self.tb.setAcceptRichText(True)
        self.tb.setOpenExternalLinks(True)

        open_dir = QAction(QIcon('open.png'), 'Open', self)
        open_dir.setShortcut('Ctrl+D')
        open_dir.setStatusTip('Open New Directory')
        open_dir.triggered.connect(self.show_dir_dialog)

        open_file = QAction(QIcon('open.png'), 'Open', self)
        open_file.setShortcut('Ctrl+F')
        open_file.setStatusTip('Open New File')
        open_file.triggered.connect(self.show_file_dialog)

        conf_font = QAction(QIcon(), 'Font', self)
        conf_font.setShortcut('Ctrl+C')
        conf_font.setStatusTip('Config font')
        conf_font.triggered.connect(self.show_font_dialog)

 
        menubar = self.menuBar()
        menubar.setNativeMenuBar(False)
        fileMenu = menubar.addMenu('&Dir')
        fileMenu.addAction(open_dir)
        fileMenu = menubar.addMenu('&File')
        fileMenu.addAction(open_file)
        confMenu = menubar.addMenu('&Config')
        confMenu.addAction(conf_font)

        pw_test_btn = QPushButton('설정 파일 취약점')
        int_ovrf_btn = QPushButton('cve 검색')
        sys_call_btn = QPushButton('시스템 콜 취약점 검출')
        buf_ovrf_btn = QPushButton('버퍼오버플로우 취약점 검출')
        endless_call_btn = QPushButton('통제 되지 않은 재귀 취약점 검출')

        pw_test_btn.clicked.connect(self.click_pw_test)
        int_ovrf_btn.clicked.connect(self.click_int_ovrf)
        sys_call_btn.clicked.connect(self.click_sys_call)
        buf_ovrf_btn.clicked.connect(self.click_buf_ovrf)
        endless_call_btn.clicked.connect(self.click_endl_recall)

        widget = QWidget()

        hbox = QHBoxLayout()
        hbox.addStretch(1)
        hbox.addWidget(pw_test_btn)
        hbox.addWidget(int_ovrf_btn)
        hbox.addWidget(sys_call_btn)
        hbox.addWidget(buf_ovrf_btn)
        hbox.addWidget(endless_call_btn)
        hbox.addStretch(1)

        vbox = QVBoxLayout(widget)
        #vbox.addStretch(3)
        vbox.addWidget(self.tb, 3)
        vbox.addLayout(hbox)
        #vbox.addStretch(1)
        self.tb.append('*' * 1000)

        self.setCentralWidget(widget)

        self.setWindowTitle('Box Layout')
        self.resize(800, 800)
        self.center()
        self.show()

    def show_dir_dialog(self):
        dname = QFileDialog.getExistingDirectory(self, 'Open directory', './')
        if dname[0]:
            self.dir_path =str(dname)
            print(dname)
            return
    def show_file_dialog(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file', './')
        if fname[0]:
            self.file_path =str(fname[0])
            print(fname[0])
            return
    def show_font_dialog(self):
        font, ok = QFontDialog.getFont()
        if ok:
           self.tb.setFont(font)
    def click_pw_test(self):
        self.append_text(self.dir_path)
        if self.dir_path == "":
            QMessageBox.information(self,'디렉토리 경로 없음','먼저 디렉토리 경로를 설정해주세요!')
            return
        else:
            result = password_checker.check_password(self.dir_path)
            self.clear_text()
            self.print_list(result['text'])
            return
    def click_int_ovrf(self):
        self.append_text(self.file_path)
        if self.file_path == "":
            QMessageBox.information(self, '파일 경로 없음', '먼저 파일 경로를 설정해주세요!')
            return
        else:
            result = int_overflow_checker.check_int_overflow(self.file_path)
            self.clear_text()
            self.print_list(result['text'])
            return
    def click_sys_call(self):
        self.append_text(self.file_path)
        if self.file_path == "":
            QMessageBox.information(self, '파일 경로 없음', '먼저 파일 경로를 설정해주세요!')
            return
        else:
            result = sys_call_checker.check_sys_call(self.file_path)
            self.clear_text()
            self.print_list(result['text'])
            return
    def click_buf_ovrf(self):
        self.append_text(self.file_path)
        if self.file_path == "":
            QMessageBox.information(self, '파일 경로 없음', '먼저 파일 경로를 설정해주세요!')
            return
        else:
            result = buf_overflow_checker.check_buf_ovfw(self.file_path)
            self.clear_text()
            self.print_list(result['text'])
            return
    def click_endl_recall(self):
        self.append_text(self.file_path)
        if self.file_path == "":
            QMessageBox.information(self, '파일 경로 없음', '먼저 파일 경로를 설정해주세요!')
            return
        else:
            result = endless_recursive_call_checker.check_endl_recall(self.file_path)
            self.clear_text()
            self.print_list(result['text'])
            return
    def append_text(self, text):
        self.tb.append(text)
    def clear_text(self):
        self.tb.clear()
    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())
    def print_list(self, _list):
        for t in _list:
            if type(t) == list:
                self.print_list(t)
            else:
                self.append_text(str(t))
        return
if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = MyApp()
    sys.exit(app.exec_())