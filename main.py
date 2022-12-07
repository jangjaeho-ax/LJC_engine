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
ResultViewlabel = ttk.LabelFrame(tab1, text="결과 확인") # 실행결과를 확인하는 콘솔창
ResultViewlabel.grid (column=0, row=3, padx=8, pady=4)

ResultViewlabel_ViewLabel = ttk.Label(ResultViewlabel, text ="Console: ")
ResultViewlabel_ViewLabel.grid(column=0, row=0, sticky="W")

ResultViewlabel_ScrollBox = scrolledtext.ScrolledText(ResultViewlabel, width=40, height=10, wrap=tk.WORD, font=('Normal',9))
ResultViewlabel_ScrollBox.grid(column=0, row=1) # 스크롤 형식의 텍스트박스 창 (콘솔창)

# 이미지 선택을 했는지 체크
IsDirSelected = False


def btn_Woman_click():
    if IsDirSelected == False:
        showerror("오류", "디렉토리를 선택해야합니다!")
    else:
        # 수정 필요@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        return




def btn_Man_click():
    if IsDirSelected == False:
        showerror("오류", "디렉토리를 선택해야합니다!")
    else:
        # 수정 필요@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        return



def open():
    global IsDirSelected
    global my_image  # 함수에서 이미지를 기억하도록 전역변수 선언 (안하면 사진이 안보임)
    global imageLabel
    global routeLabel
    panedwindow1.filename = filedialog.askdirectory(initialdir='', title='디렉토리 선택')

    # 선택을 했을때만 실행
    if panedwindow1.filename != "":
        IsDirSelected = True
        routeLabel["text"] = panedwindow1.filename
        routeLabel.pack()  # 파일경로 view

        # 이미지 사이즈 조정
        init_input_img = Image.open(panedwindow1.filename)
        my_image = ImageTk.PhotoImage(init_input_img.resize((320, 320)))
        imageLabel["image"] = my_image
        imageLabel.pack()  # 사진 view
        # imageLabel.pack_forget()


def open():
    global IsDirSelected
    global my_image  # 함수에서 이미지를 기억하도록 전역변수 선언 (안하면 사진이 안보임)
    global imageLabel
    global routeLabel
    panedwindow1.dirname = filedialog.askdirectory(initialdir='', title='디렉토리 선택')

    # 선택을 했을때만 실행
    if panedwindow1.dirname != "":
        IsDirSelected = True
        routeLabel["text"] = panedwindow1.dirname
        routeLabel.pack()  # 파일경로 view

        # 이미지 사이즈 조정
        init_input_img = Image.open(panedwindow1.dirname)
        my_image = ImageTk.PhotoImage(init_input_img.resize((320, 320)))
        imageLabel["image"] = my_image
        imageLabel.pack()  # 사진 view
        # imageLabel.pack_forget()


btn_create = Button(window, text='여자 이모지 만들기', command=btn_Woman_click)
btn_create.pack(side="bottom", padx="10", pady="10", fill="x")

btn_create = Button(window, text='남자 이모지 만들기', command=btn_Man_click)
btn_create.pack(side="bottom", padx="10", pady="10", fill="x")

label_create = Label(window, text="## 성별에 맞게 선택해주세요 ##")
label_create.pack(side="bottom", fill="x")

btn_load = Button(window, text='증명사진 불러오기', command=open)
btn_load.pack(side="bottom", padx="15", pady="15", fill="x")

label_create = Label(window, text="## 증명사진을 골라주세요 ##")
label_create.pack(side="bottom", fill="x")

window.mainloop()