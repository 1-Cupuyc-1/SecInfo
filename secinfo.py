from tkinter import *
from tkinter import ttk as ttk
from tkinter import messagebox as messagebox
import string
import json
import sys
import crypto_secinfo as crypto


ADMIN = "ADMIN"             # Имя учетки администратора (логин)
dict_bd = {}                # Переменная в которой хранится бд после извлечения данных из файла 
BD_PATH = "bd_secinfo.dat"  # Путь до файла где хранится БД

def LoadBDtxt(dict_bd:dict = {}):
    def Record():
        file.seek(0)
        dict_bd.update(json.load(file)) #так как оригинальный и локальный dict_bd ссылаются на один и тот же объект, изменяя второй - меняем и первый (dict_bd = {...} - работает как новое присвоение и разрывает связь оригинаьного и локального dict_bd)
    try:    
        with open("bd_secinfo.txt", "r+", encoding="utf-8") as file:
            Record()
    except FileNotFoundError as ex: # если нет такого файла - создается файл и сразу инифиализуется в него данные по администратору
        with open("bd_secinfo.txt", "w+", encoding="utf-8") as file: 
            json.dump({ADMIN: {"password": "", "block": 0, "limit": 0}}, file)
            Record()
def SaveBDtxt():
    with open("bd_secinfo.txt", "w+", encoding="utf-8") as file:
        json.dump(dict_bd, file)
def PasswordLimiter(text):
    has_letter = any(c.isalpha() for c in text)                 # True - если есть хотя бы 1 латинская буква иначе False
    has_punct  = any(c in string.punctuation for c in text)     # True - если есть хотя бы 1 знак пунктуации иначе False
    return has_letter and has_punct                             # Возврат результата булевой операции 
def SaveBDdat(passphrase: str):
    """Шифрует dict_bd и перезаписывает файл (новый salt при каждом сохранении)."""
    text = json.dumps(dict_bd, ensure_ascii=False)
    crypto.encrypt_to_file(BD_PATH, text.encode("utf-8"), passphrase)
def LoadBDdat(passphrase: str, dict_bd: dict) -> bool:
    """Расшифровывает БД в dict_bd (на месте).
    Возвращает True, если фраза верна (в данных есть администратор)."""
    def Record():
        raw = crypto.decrypt_from_file(BD_PATH, passphrase)          # bytes
        data = json.loads(raw.decode("utf-8"))                # bytes -> str -> dict
        if not isinstance(data, dict) or ADMIN not in data:   # проверка фразы по наличию админа
            raise ValueError("admin not found")
        dict_bd.clear()
        dict_bd.update(data)

    try:
        Record()
    except FileNotFoundError:
        # первый запуск: создаём БД с админом и шифруем введённой фразой
        default = {ADMIN: {"password": "", "block": 0, "limit": 0}}
        crypto.encrypt_to_file(BD_PATH, json.dumps(default).encode("utf-8"), passphrase)
        Record()
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, IndexError):
        return False        # мусор после расшифровки = неверная фраза
    return True


def InputKey():
    def Action():
        if LoadBDdat(passphrase.get(), dict_bd):
            messagebox.showinfo(title="Уведомление", message="Введена правильная парольная фраза.\nДоступ открыт")
        else:
            messagebox.showerror(title="Ошибка", message="Введена неправильная парольная фраза.\nДоступ закрыт")
        window.destroy()

    window = Toplevel(root)
    window.title("Ввод парольной фразы")
    window.geometry("350x100")

    window.rowconfigure(index=[0,1], weight=1)
    window.columnconfigure(index=0, weight=3)
    window.columnconfigure(index=1, weight=7)

    style = {
        "sticky": "we",
        "padx": 5,
        "pady": 5
    }

    ttk.Label(window, text="Парольная фраза:", anchor="center").grid(row=0, column=0, **style)

    key = ttk.Entry(window, textvariable=passphrase, show='*')
    key.grid(row=0, column=1, **style)

    ttk.Button(window, text="Подтвердить", command=Action).grid(row=1, column=0, columnspan=2)

    window.protocol("WM_DELETE_WINDOW", lambda: window.destroy())   # закрытие окна = конец с ошибкой

    window.grab_set()               # блок ввод в остальных окнах
    root.wait_window(window)        # ожидание закрытия диалога

def DefaultMenuBar():
    def Reference():
        ClearFrameAndChangeName(f"Информация о программе")

        ttk.Label(main_frame, anchor='center', text="Подготовил:\t Студент 4 курса ИБД-23-01 Гераськин А.А.\n\n" \
        "Ограничение на пароль:\t Наличие букв и знаков препинания \n\n").pack(expand=1, fill='both')

    window.option_add("*tearOff", FALSE)
    action_menu = Menu(main_menu)

    ref_menu = Menu(main_menu)
    ref_menu.add_command(label="О программе", command=Reference)

    
    main_menu.insert_cascade(0,label="Действия", menu=action_menu)
    main_menu.insert_cascade(2, label="Справка", menu=ref_menu)
def RefreshMenuBar(login:str = ""):
    def ChangeUser():
        RefreshMenuBar()
        for widget in window.winfo_children():
            if isinstance(widget, Toplevel):
                widget.destroy()
        LoginSystem()

    main_menu.delete(0, 1)
    action_menu = Menu(main_menu)
    if login != "":
        action_menu.add_cascade(label="Смена пароля", command=lambda: ChangePassword(login, Workspace))
    if login == ADMIN:
        action_menu.add_cascade(label="Управление пользователями", command=ControlPanel)
    action_menu.add_cascade(label="Смена пользователя", command=ChangeUser)
    action_menu.add_separator()
    action_menu.add_cascade(label="Выход", command=root.destroy)


    main_menu.insert_cascade(1, label="Действия", menu=action_menu )
def ClearFrameAndChangeName(text:str = ""):
    for widget in main_frame.winfo_children():
        widget.destroy()
    window.title(text)
def LoginSystem():
    def CheckPassword():
        lgn = login.get()
        if not (lgn in dict_bd): # Нет логина в переменной dict_bd => нет в файле
            print(dict_bd, lgn)
            messagebox.showerror(title="Ошибка", message="Неверный логин")
            login.delete(0, END)
            password.delete(0, END)
        elif dict_bd[lgn]["password"] == "": # первый вход в систему под этим логином
            messagebox.showinfo(title="Уведомление", message="Необходимо установить пароль")
            SetPassword(lgn)
        elif dict_bd[lgn]["password"] != password.get():  # неправильный пароль
            messagebox.showerror(title="Ошибка", message="Неверный пароль")
            login.delete(0, END)
            password.delete(0, END)
        elif dict_bd[lgn]["block"] == 1: # Админ заблокировал данную учетную запись 
            messagebox.showerror(title="Ошибка", message="Учетная запись заблокирована")
            login.delete(0, END)
            password.delete(0, END)
        elif dict_bd[lgn]["limit"] == 1 and not PasswordLimiter(dict_bd[lgn]["password"]): # несоответсвие ограничениям на пароль
            messagebox.showinfo(title="Уведомление", message="На вашу учетку наложено ограничение на пароль - он должен отвечать следующим требованиям: Наличие букв и знаков препинания")
            ChangePassword(lgn)
        else: # Вход в систему
            Workspace(lgn)
    def SetPassword(login:str):
        def CheckPasswords():
            if new_password.get() == "" or confirmation.get() == "":
                messagebox.showwarning(title="Предупреждение", message="Заполните поля ввода для паролей")
            elif new_password.get() == confirmation.get():
                dict_bd[login]["password"] = new_password.get()
                SaveBDdat(passphrase.get())
                messagebox.showinfo(title="Успех", message="Пароль успешно установлен")
                LoginSystem()
            elif new_password.get() != confirmation.get():
                messagebox.showerror(title="Ошибка", message="Пароли не совпали.\nПопробуйте вновь")
                new_password.delete(0, END)
                confirmation.delete(0, END)
            else:
                messagebox.showerror(title="Ошибка", message="Пароль должен соответствовать следующим требованиям: Наличие букв и знаков препинания")
                new_password.delete(0, END)
                confirmation.delete(0, END)
        def Cancel():
            LoginSystem()

        ClearFrameAndChangeName("Установка пароля")

        main_frame.rowconfigure(index=[0,1,2], weight=1)
        main_frame.columnconfigure(index=0, weight=3)
        main_frame.columnconfigure(index=1, weight=7)

        style = {
            "sticky": "we",
            "padx": 5,
            "pady": 5
        }

        ttk.Label(main_frame, text="Новый пароль:", anchor="center").grid(row=0, column=0, **style)
        ttk.Label(main_frame, text="Подтверждение:", anchor="center").grid(row=1, column=0, **style)

        new_password = ttk.Entry(main_frame, show='*')
        new_password.grid(row=0, column=1, **style)
        confirmation = ttk.Entry(main_frame, show='*')
        confirmation.grid(row=1, column=1, **style)

        ttk.Button(main_frame, text="Ok", command=CheckPasswords).grid(row=2, column=0)
        ttk.Button(main_frame, text="Отмена", command=Cancel).grid(row=2, column=1)

    ClearFrameAndChangeName("Вход в систему")
    RefreshMenuBar()

    main_frame.rowconfigure(index=[0,1,2], weight=1)
    main_frame.columnconfigure(index=0, weight=3)
    main_frame.columnconfigure(index=1, weight=7)

    style = {
        "sticky": "we",
        "padx": 5,
        "pady": 5
    }

    ttk.Label(main_frame, text="Логин:", anchor="center").grid(row=0, column=0, **style)
    ttk.Label(main_frame, text="Пароль:", anchor="center").grid(row=1, column=0, **style)

    login = ttk.Entry(main_frame)
    login.grid(row=0, column=1, **style)
    password = ttk.Entry(main_frame, show='*')
    password.grid(row=1, column=1, **style)

    ttk.Button(main_frame, text="Войти", command=CheckPassword).grid(row=2, column=0, columnspan=2)
def Workspace(login:str):
    ClearFrameAndChangeName(f"Защита информации - [{login}]")
    RefreshMenuBar(login)

    ttk.Label(main_frame, text=f"{login} в системе").pack(expand=1)
def ControlPanel():
    def UpdateUserSetting(login, setting, state):
        dict_bd[login][setting] = int(state)
        SaveBDdat(passphrase.get())
    def AddUser():
        global dict_bd
        login_user = entry_field.get().strip() 
        if login_user == "":
            messagebox.showwarning(title="Предупреждение", message="Нельзя записать пользователя с пустым логином")
        elif dict_bd.get(login_user):
            messagebox.showwarning(title="Предупреждение", message="Пользователь с таким именем уже есть")
        else:
            dict_bd.update({login_user: {"password": "", 
                        "block": 0,
                        "limit": 0}})
            print(dict_bd)
            SaveBDdat(passphrase.get())
            ControlPanel()
    
    ClearFrameAndChangeName("Панель управления")

    frame1 = ttk.Frame(main_frame)
    frame1.columnconfigure(index=[0,1,2], weight=1)

    frame2 = ttk.Frame(main_frame)
    frame2.columnconfigure(index=1, weight=1)

    style = {
        "sticky": "we",
        "padx": 5,
        "pady": 2
    }
    ttk.Label(frame1, text="Логин").grid(row=0, column=0, **style)
    ttk.Label(frame1, text="Блокировка").grid(row=0, column=1, **style)
    ttk.Label(frame1, text="Ограничения на пароль").grid(row=0, column=2, **style)

    i = 0
    for key, value in dict_bd.items():
        i += 1
        ttk.Label(frame1, text=key).grid(row=i, column=0, **style)
        # Переменные состояния чекбоксов
        block_var = BooleanVar(value=int(value["block"]) == 1)
        limit_var = BooleanVar(value=int(value["limit"]) == 1)

        state = "disabled" if key == ADMIN else "normal"

        # Блокировка пользователя
        ttk.Checkbutton(frame1, variable=block_var, state=state, command=lambda k=key, v=block_var: UpdateUserSetting(k, "block", v.get())).grid(row=i, column=1, **style)

        # Ограничение пароля
        ttk.Checkbutton(frame1, variable=limit_var, state=state, command=lambda k=key, v=limit_var: UpdateUserSetting(k, "limit", v.get())).grid(row=i, column=2, **style)

    ttk.Label(frame2, text="Логин: ").grid(row=0, column=0)
    entry_field = ttk.Entry(frame2)
    entry_field.grid(row=0, column=1, **style)
    ttk.Button(frame2, text="Добавить пользователя", command=AddUser).grid(row=0, column=2)

    frame1.pack(expand=1, fill="both", side="top")
    frame2.pack(fill="x", side='bottom')
def ChangePassword(login:str, last_window = LoginSystem):
    def CheckPasswords():
            if new_password.get() == "" or confirmation.get() == "":
                messagebox.showwarning(title="Предупреждение", message="Заполните поля ввода для паролей")
            elif last_password.get() != dict_bd[login]["password"]:
                messagebox.showerror(title="Ошибка", message="Неверно веден старый пароль\nПопробуйте вновь")
                last_password.delete(0, END)
                new_password.delete(0, END)
                confirmation.delete(0, END)
            elif new_password.get() != confirmation.get():
                messagebox.showwarning(title="Ошибка", message="Новый пароль не совпал\nПопробуйте вновь")
                last_password.delete(0, END)
                new_password.delete(0, END)
                confirmation.delete(0, END)
            elif dict_bd[login]["limit"] == 1 and not PasswordLimiter(new_password.get()):
                messagebox.showinfo(title="Уведомление", message="На вашу учетку наложено ограничение на пароль - он должен отвечать следующим требованиям: Наличие букв и знаков препинания")
                last_password.delete(0, END)
                new_password.delete(0, END)
                confirmation.delete(0, END)           
            else:
                dict_bd[login]["password"] = new_password.get()
                SaveBDdat(passphrase.get())
                messagebox.showinfo(title="Успех", message="Пароль успешно изменен")
                if last_window == LoginSystem:
                    last_window()
                else:
                    last_window(login)

    ClearFrameAndChangeName("Смена пароля")

    main_frame.rowconfigure(index=[0,1,2,3], weight=1)
    main_frame.columnconfigure(index=0, weight=3)
    main_frame.columnconfigure(index=1, weight=7)

    style = {
        "sticky": "we",
        "padx": 5,
        "pady": 5
    }
    
    ttk.Label(main_frame, text="Старый пароль:", anchor="center").grid(row=0, column=0, **style)
    ttk.Label(main_frame, text="Новый пароль:", anchor="center").grid(row=1, column=0, **style)
    ttk.Label(main_frame, text="Подтверждение:", anchor="center").grid(row=2, column=0, **style)

    last_password = ttk.Entry(main_frame, show='*')
    last_password.grid(row=0, column=1, **style) 
    new_password = ttk.Entry(main_frame, show='*')
    new_password.grid(row=1, column=1, **style)
    confirmation = ttk.Entry(main_frame, show='*')
    confirmation.grid(row=2, column=1, **style)

    
    #ttk.Button(main_frame, text="Отмена", command=lambda: Workspace(login)).grid(row=3, column=0)
    ttk.Button(main_frame, text="Ok", command=CheckPasswords).grid(row=3, column=1)

root = Tk()
root.withdraw()
passphrase = StringVar()


InputKey()
if dict_bd == {}:
    root.destroy()
    sys.exit(1)

window = Toplevel(root)
window.geometry("350x250")

main_menu = Menu()
window.config(menu=main_menu)
DefaultMenuBar()

main_frame = ttk.Frame(window)
main_frame.pack(expand=1, fill="both")

LoginSystem()
#Workspace(admin)

root.mainloop()