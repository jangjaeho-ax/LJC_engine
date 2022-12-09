from mimetypes import init
from tkinter import *
from PIL import ImageTk, Image
from tkinter import filedialog
from tkinter import ttk
from tkinter import scrolledtext
from tkinter.messagebox import *
import numpy as np


# window 기본 설정
window = Tk()
window.title("이모지 만들어주는 프로그램")
window.geometry("640x640+650+200")
window.resizable(False, False)
init_image = "./"

panedwindow1 = PanedWindow(width="300", height="300", relief="sunken", bd=5)
panedwindow1.pack(expand=True)

'''
init_image = Image.open('./camera.png')
imageForInit = ImageTk.PhotoImage(init_image.resize((320, 320)))
imageLabel = Label(panedwindow1, image=imageForInit)
imageLabel.pack()
'''
routeLabel = Label(panedwindow1)

# 이미지 선택을 했는지 체크
IsDirSelected = False


def btn_test_click():
    if IsDirSelected == False:
        showerror("오류", "디렉토리를 선택해야합니다!")
    else:
        # 수정 필요@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        print(routeLabel['text'])
        return




def btn_Man_click():
    if IsDirSelected == False:
        showerror("오류", "디렉토리를 선택해야합니다!")
    else:
        # 수정 필요@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        return



def open():
    global IsDirSelected
    global routeLabel
    panedwindow1.filename = filedialog.askdirectory(initialdir='', title='디렉토리 선택')

    # 선택을 했을때만 실행
    if panedwindow1.filename != "":
        IsDirSelected = True
        routeLabel["text"] = panedwindow1.filename
        routeLabel.pack()  # 파일경로 view




btn_create = Button(window, text='password 분석', command=btn_test_click)
btn_create.pack(side="bottom", padx="10", pady="10", fill="x")

btn_create = Button(window, text='system call injection 취약점 검출', command=btn_Man_click)
btn_create.pack(side="bottom", padx="10", pady="10", fill="x")

label_create = Label(window, text="## 성별에 맞게 선택해주세요 ##")
label_create.pack(side="bottom", fill="x")

btn_load = Button(window, text='증명사진 불러오기', command=open)
btn_load.pack(side="bottom", padx="15", pady="15", fill="x")

label_create = Label(window, text="## 증명사진을 골라주세요 ##")
label_create.pack(side="bottom", fill="x")

window.mainloop()