import sqlite3
import time
import base64
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

# Establish connection with database
conn = sqlite3.connect("pass_safe.db")
conn.row_factory = sqlite3.Row
cur = conn.cursor()

# Set encoding for program
encoding = 'utf-8'

# Function to generate encryption key and password hash form password string
# Returns key, pass_hash, f (for Fernet encryption)
def setkey(password):
    salt = hashlib.sha256(password.encode(encoding)).hexdigest()
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),length=32,salt=bytes(salt.encode(encoding)),iterations=10000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode(encoding)))
    pass_hash = hashlib.sha256(key).hexdigest()
    f = Fernet(key)
    return key, pass_hash, f


# Check if password table exists in database
cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='master'")
rows = cur.fetchall()
if len(rows) == 0:
    # Create encryption key and password hash from user entered password
    masterpass = input("Enter Master Password: ")
    confirmation = input("Confirm Master Password: ")
    # If password and confirmation do not match, quit program
    if masterpass != confirmation:
        print("Error: Entered passwords did not match")
        raise SystemExit
    # Create encryption key from master password and hash password for storage
    key, masterpass_hash, f = setkey(masterpass)
    # Create password table in db to store encrypted master password
    cur.execute("CREATE TABLE master (masterpass TEXT)")
    cur.execute("INSERT INTO master (masterpass) VALUES (:masterpass)", {"masterpass": f.encrypt(masterpass_hash.encode(encoding))})
    conn.commit()
else:
    password = input("Enter Master Password: ")
    key, pass_hash, f = setkey(password)
    cur.execute("SELECT * FROM master")
    row = cur.fetchone()
    # Authenticate user by comparing entered password hash and stored hash
    if pass_hash != f.decrypt(row['masterpass']).decode(encoding):
        print("Error: Password entered was incorrect")
        raise SystemExit

# Creates table for first time
cur.execute("CREATE TABLE IF NOT EXISTS passwords (password TEXT, username TEXT, email TEXT, appname TEXT)")
wait = 1.5

# Queries user for request
#while True:
command = "CAT"


# ADD pasword for new account
if command.upper() == "ADD":
    appname = input("Enter account site/app name: ").lower()
    
    # Check for existing account
    cur.execute("SELECT * FROM passwords WHERE appname = :appname", {"appname": appname})
    rows = cur.fetchall()
    if len(rows) != 0:
        print(f"An account already exists in the database for {appname}")
        time.sleep(wait)
    # If no account already exist, continue
    else:
        username = input("Enter account username: ")
        email = input("Enter account email: ")
        password = input("Enter account password: ")
        cur.execute("INSERT INTO passwords (password, username, email, appname) VALUES (:password, :username, :email, :appname)", {"password": f.encrypt(password.encode(encoding)), "username": username, "email": email, "appname": appname})
        conn.commit()
        print(f"Account information has been entered for {appname}")
        time.sleep(wait)

# FIND password for existing account
elif command.upper() == "FIND":
    appname = input("Enter the app/site name of the account: ")
    cur.execute("SELECT * FROM passwords WHERE appname = :appname", {"appname": appname})
    rows = cur.fetchall()
    if len(rows) == 0:
        print(f"No account exists in the database for {appname}")
        time.sleep(wait)
    else:
        cur.execute("SELECT password FROM passwords WHERE appname = :appname", {"appname": appname})
        rows = cur.fetchone()
        print(f"password: {f.decrypt(rows['password']).decode(encoding)}")
        time.sleep(wait)

# LIST accounts under provided email
elif command.upper() == "LIST":
    email = input("Enter the email you'd like to check accounts for: ")
    cur.execute("SELECT * FROM passwords WHERE email = :email", {"email": email})
    rows = cur.fetchall()
    if len(rows) == 0:
        print(f"No account exists in the database under {email}")
        time.sleep(wait)
    else:
        for row in rows:
            print(f"account: {row['appname']}, username: {row['username']}")
        time.sleep(wait)

# DELETE account information
elif command.upper() == "DELETE":
    appname = input("Enter the app/site name of the account: ")
    cur.execute("SELECT * FROM passwords WHERE appname = :appname", {"appname": appname})
    rows = cur.fetchall()
    if len(rows) == 0:
        print(f"No account exists in the database for {appname}")
        time.sleep(wait)
    else:
        cur.execute("DELETE FROM passwords WHERE appname = :appname", {"appname": appname})
        conn.commit()
        print(f"Information for {appname} account has been deleted")
        time.sleep(wait)

# EXIT
elif command.upper() == "EXIT":
    cur.close()
    raise SystemExit
# TODO entering wrong password now gives cryptography.fernet.InvalidToken error (when trying to decrypt masterpass) - for useability, find a way to make this a customized error message

### Here starts the GUI stuff
# Create app window
class PassManager (tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        container = tk.Frame(self)
        self.winfo_toplevel().title("Password Manager 3000")
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        # Create frames and stack frames for app
        for F in (LoginPage, RegisterPage, MainPage, AddPage, FindPage, ListPage, DeletePage):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        # Show LoginPage frame first
        self.show_frame(LoginPage)
    # Function to raise called frame to top (show user)
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

# Create LoginPage
class LoginPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)                
        
        lbl_email = tk.Label(self, text="Email:")
        ent_email = tk.Entry(self, width=40)
        lbl_email.grid(row=1,column=0, sticky='e')
        ent_email.grid(row=1,column=1)
        lbl_password = tk.Label(self, text="Password:")
        ent_password = tk.Entry(self, width=40)
        lbl_password.grid(row=2,column=0, sticky='e')
        ent_password.grid(row=2,column=1)
        #btn_login = tk.Button(self, text="Login", command=login(ent_email.get(), ent_password.get(), controller))
        btn_login = tk.Button(self, text="Login", command=lambda: self.login(ent_email, ent_password))
        btn_login.grid(row=3,column=1, pady=5)
        btn_register = tk.Button(self, text="Don't have an account?\nRegister")      
        btn_register.grid(row=4,column=1, pady=5)
    # Login Function
    def login(self, ent_email, ent_password):
        email = ent_email.get()
        password = ent_password.get()
        print(f"{email} {password}")
        if email == '' or password == '':
            messagebox.showerror("Login Error", "Please enter a valid email and password")
        
        self.controller.show_frame(RegisterPage)

# Create RegisterPage
class RegisterPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_email = tk.Label(self, text="Email:")
        ent_email = tk.Entry(self, width=40)
        lbl_email.grid(row=1,column=0, sticky='e')
        ent_email.grid(row=1,column=1)
        lbl_password = tk.Label(self, text="Password:")
        ent_password = tk.Entry(self, width=40)
        lbl_password.grid(row=2,column=0, sticky='e')
        ent_password.grid(row=2,column=1)
        lbl_confirmation = tk.Label(self, text="Confirmation:")
        ent_confirmation = tk.Entry(self, width=40)
        lbl_confirmation.grid(row=3,column=0, sticky='e')
        ent_confirmation.grid(row=3,column=1)
        btn_register = tk.Button(self, text="Register")
        btn_register.grid(row=4,column=1, pady=5)

# Create MainPage
class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        btn_add = tk.Button(self, text="ADD")
        lbl_add = tk.Label(self, text="a new account")
        btn_add.grid(row=1,column=0, sticky='ew')
        lbl_add.grid(row=1,column=1, sticky='w')
        btn_find = tk.Button(self, text="FIND")
        lbl_find = tk.Label(self, text="a password for existing account")
        btn_find.grid(row=2,column=0, sticky='ew')
        lbl_find.grid(row=2,column=1, sticky='w')
        btn_list = tk.Button(self, text="LIST")
        lbl_list = tk.Label(self, text="accounts registered to a username/email")
        btn_list.grid(row=3,column=0, sticky='ew')
        lbl_list.grid(row=3,column=1, sticky='w')
        btn_delete = tk.Button(self, text="DELETE")
        lbl_delete = tk.Label(self, text="account information")
        btn_delete.grid(row=4,column=0, sticky='ew')
        lbl_delete.grid(row=4,column=1, sticky='w')

# Create AddPage
class AddPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_app = tk.Label(self, text="Account/App Name:")
        ent_app = tk.Entry(self, width=40)
        lbl_app.grid(row=1,column=0, sticky='e')
        ent_app.grid(row=1,column=1)
        lbl_username = tk.Label(self, text="Username:")
        ent_username = tk.Entry(self, width=40)
        lbl_username.grid(row=2,column=0, sticky='e')
        ent_username.grid(row=2,column=1)
        lbl_email = tk.Label(self, text="Email:")
        ent_email = tk.Entry(self, width=40)
        lbl_email.grid(row=3,column=0, sticky='e')
        ent_email.grid(row=3,column=1)
        lbl_password = tk.Label(self, text="Password:")
        ent_password = tk.Entry(self, width=40)
        lbl_password.grid(row=4,column=0, sticky='e')
        ent_password.grid(row=4,column=1)
        lbl_confirmation = tk.Label(self, text="Confirmation:")
        ent_confirmation = tk.Entry(self, width=40)
        lbl_confirmation.grid(row=5,column=0, sticky='e')
        ent_confirmation.grid(row=5,column=1)
        btn_submit = tk.Button(self, text="Submit")
        btn_submit.grid(row=6, column=1, pady=5)

# Create FindPage
class FindPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_app = tk.Label(self, text="Account/App Name:")
        ent_app = tk.Entry(self, width=40)
        lbl_app.grid(row=1,column=0, sticky='e')
        ent_app.grid(row=1,column=1)
        btn_submit = tk.Button(self, text="Submit")
        btn_submit.grid(row=2, column=1, pady=5)

# Create ListPage
class ListPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        # Creating dropdown menu for user to select Username/Email
        variable = tk.StringVar(self)
        variable.set("Username")
        dropdown = tk.OptionMenu(self, variable, "Username", "Email")
        ent_dropdown = tk.Entry(self, width=40)
        dropdown.grid(row=1, column=0, sticky='ew')
        ent_dropdown.grid(row=1,column=1)
        btn_submit = tk.Button(self, text="Submit")
        btn_submit.grid(row=2, column=1, pady=5)

# Create DeletePage
class DeletePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_app = tk.Label(self, text="Account/App Name:")
        ent_app = tk.Entry(self, width=40)
        lbl_app.grid(row=1,column=0, sticky='e')
        ent_app.grid(row=1,column=1)
        btn_delete = tk.Button(self, text="Delete")
        btn_delete.grid(row=2, column=1, pady=5)

app = PassManager()
app.mainloop()