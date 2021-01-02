# Imports
from pathlib import Path
import sqlite3, time, base64, hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox

# Creates path for database in .py folder
dbname = "PasswordManager3000"
dbpath = (Path(__file__).parent / dbname).with_suffix('.db')
# Establish connection with database
conn = sqlite3.connect(dbpath)
conn.row_factory = sqlite3.Row
cur = conn.cursor()
#Create user and password tables in database
cur.execute("CREATE TABLE IF NOT EXISTS users (userid NUMERIC, email TEXT, password TEXT)")
cur.execute("CREATE TABLE IF NOT EXISTS passwords (userid NUMERIC, app TEXT, username TEXT, email TEXT, password TEXT)")
# Set encoding for program
encoding = 'utf-8'
# Initiate global user variables to access and encrypt/decrypt user passwords
userid = None
key = None
f = None

# Function to generate encryption key and password hash from password string: returns key, f (for Fernet encryption)
def setkey(password):
    salt = hashlib.sha256(password.encode(encoding)).hexdigest()
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),length=32,salt=bytes(salt.encode(encoding)),iterations=10000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode(encoding)))
    f = Fernet(key)
    return key, f

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
        # Create and stack frames for app
        for F in (SignInPage, SignUpPage, MainPage, AddPage, FindPage, DeletePage):
            frame = F(parent=container, controller=self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")
        # Show LoginPage frame first
        self.show_frame(SignInPage)
    # Function to raise called frame to top (show user)
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()

# Create SignInPage
class SignInPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4], weight=1)
        self.grid_columnconfigure([0, 1, 2], weight=1)                
        lbl_header = tk.Label(self, text="Sign In", font=("Calibri", 14))
        lbl_header.grid(row=0, column=1, columnspan=2, sticky='ew')
        lbl_email = tk.Label(self, text="Email:")
        ent_email = tk.Entry(self, width=40)
        lbl_email.grid(row=1,column=0, sticky='e')
        ent_email.grid(row=1,column=1, columnspan=2)
        lbl_password = tk.Label(self, text="Password:")
        ent_password = tk.Entry(self, show=u"\u2022", width=40)
        lbl_password.grid(row=2,column=0, sticky='e')
        ent_password.grid(row=2,column=1, columnspan=2)
        btn_signin = tk.Button(self, text="Sign In", command=lambda: self.signin(ent_email, ent_password))
        btn_signin.grid(row=4,column=1, sticky='ew')
        btn_signup = tk.Button(self, text="Sign Up", command=lambda: self.gotosignup(ent_email, ent_password))      
        btn_signup.grid(row=4,column=2, padx=10, sticky='ew')
    # Sign In Function
    def signin(self, ent_email, ent_password):
        global userid
        global key
        global f
        email = ent_email.get().lower()
        password = ent_password.get()
        # Checks if email has an accout in users
        if len(cur.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchall()):
            # Checks if hashed password matches stored value in users
            if hashlib.sha256(password.encode(encoding)).hexdigest() == cur.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchone()["password"]:
                # Sets userid and encryption key, f from password
                userid = cur.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchone()["userid"]
                key, f = setkey(password)
                self.controller.show_frame(MainPage)
                ent_email.delete(0,"end")
                ent_password.delete(0,"end")
            else:
                messagebox.showerror("Sign In Error", "Incorrect password entered")
        else:
            messagebox.showerror("Sign In Error", "No account could be found for this email")
    def gotosignup(self, ent_email, ent_password):
        self.controller.show_frame(SignUpPage)
        ent_email.delete(0,"end")
        ent_password.delete(0,"end")

# Create SignUpPage
class SignUpPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_header = tk.Label(self, text="Sign Up", font=("Calibri", 14))
        lbl_header.grid(row=0, column=1, sticky='ew')
        lbl_email = tk.Label(self, text="Email:")
        ent_email = tk.Entry(self, width=40)
        lbl_email.grid(row=1,column=0, sticky='e')
        ent_email.grid(row=1,column=1, columnspan=3)
        lbl_password = tk.Label(self, text="Password:")
        ent_password = tk.Entry(self, show=u"\u2022", width=40)
        lbl_password.grid(row=2,column=0, sticky='e')
        ent_password.grid(row=2,column=1, columnspan=3)
        lbl_confirmation = tk.Label(self, text="Confirmation:")
        ent_confirmation = tk.Entry(self, show=u"\u2022", width=40)
        lbl_confirmation.grid(row=3,column=0, sticky='e')
        ent_confirmation.grid(row=3,column=1, columnspan=3)
        btn_signup = tk.Button(self, text="Sign Up", command=lambda: self.signup(ent_email, ent_password, ent_confirmation))
        btn_signup.grid(row=4,column=1, padx=10, pady=5, sticky='ew')
        btn_back = tk.Button(self, text="Back", command=lambda: self.gotosignin(ent_email, ent_password, ent_confirmation))
        btn_back.grid(row=4,column=0, padx=10, pady=5, sticky='ew')
    # Sign Up Function
    def signup(self, ent_email, ent_password, ent_confirmation):
        global userid
        global key
        global f
        email = ent_email.get().lower()
        password = ent_password.get()
        confirmation = ent_confirmation.get()
        if email == "" or password == "":
            messagebox.showerror("Sign Up Error", "Please enter an email and password to register an account ")
        # Checks entered password and confirmation match
        elif password != confirmation:
            messagebox.showerror("Sign Up Error", "Entered passwords do not match")
        # Checks email does not have an accout already in users
        elif len(cur.execute("SELECT * FROM users WHERE email = :email", {"email": email}).fetchall()):
            messagebox.showerror("Sign Up Error", "This email is already registered with an account")
        else:
            # If first ever account, assigns userid as 0
            if len(cur.execute("SELECT * from users WHERE email = :email", {"email": email}).fetchall()) == 0:
                userid = 0
            # If not first account, assigns next userid numerically and adds user to users table
            else:
                userid = cur.execute("SELECT MAX(userid) from users").fetchall()["MAX(userid)"] + 1
            key, f = setkey(password)
            cur.execute("INSERT INTO users (userid, email, password) VALUES (:userid, :email, :password)", {"userid": userid, "email": email, "password": hashlib.sha256(password.encode(encoding)).hexdigest()})
            conn.commit()
            messagebox.showinfo("Sign Up Complete", "Welcome! "+email+" is now registered.\nTo begin using PasswordManager3000, please Login")
            self.controller.show_frame(SignInPage)
            ent_email.delete(0,"end")
            ent_password.delete(0,"end")
            ent_confirmation.delete(0,"end")
    def gotosignin(self, ent_email, ent_password, ent_confirmation):
        self.controller.show_frame(SignInPage)
        ent_email.delete(0,"end")
        ent_password.delete(0,"end")
        ent_confirmation.delete(0,"end")

# Create MainPage
class MainPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_header = tk.Label(self, text="Select Option", font=("Calibri", 14))
        lbl_header.grid(row=0, column=0, columnspan=2, sticky='ew')
        btn_add = tk.Button(self, text="ADD", command=lambda: controller.show_frame(AddPage))
        lbl_add = tk.Label(self, text="a new account")
        btn_add.grid(row=1,column=0, padx=10, sticky='ew')
        lbl_add.grid(row=1,column=1, sticky='w')
        btn_find = tk.Button(self, text="FIND", command=lambda: controller.show_frame(FindPage))
        lbl_find = tk.Label(self, text="a password for existing account")
        btn_find.grid(row=2,column=0, padx=10, sticky='ew')
        lbl_find.grid(row=2,column=1, sticky='w')
        btn_list = tk.Button(self, text="LIST", command=lambda: self.listf())
        lbl_list = tk.Label(self, text="accounts registered to a username/email")
        btn_list.grid(row=3,column=0, padx=10, sticky='ew')
        lbl_list.grid(row=3,column=1, sticky='w')
        btn_delete = tk.Button(self, text="DELETE", command=lambda: controller.show_frame(DeletePage))
        lbl_delete = tk.Label(self, text="account information")
        btn_delete.grid(row=4,column=0, padx=10, sticky='ew')
        lbl_delete.grid(row=4,column=1, sticky='w')
        btn_signout = tk.Button(self, text="Sign Out", command=lambda: self.signout())
        btn_signout.grid(row=5,column=0, padx=10, pady=5, sticky='ew')
    # Sign Out Function
    def signout(self):
        global userid
        global key
        global f
        # Clear user information and return to SignInPage
        userid = None
        key = None
        f = None
        messagebox.showinfo("Signed Out", "You have been successfully signed out")
        self.controller.show_frame(SignInPage)
    # List Function
    def listf(self):
        global userid
        rows = cur.execute("SELECT * FROM passwords where userid = :userid", {"userid": userid}).fetchall()
        if len(rows) == 0:
            messagebox.showerror("Search Error", "No accounts found")
        else:
            apps = str()
            for row in rows:
                app = row["app"]
                apps = apps+"\n"+app
            messagebox.showinfo("Search Results", "The following accounts were found:\n"+apps)

# Create AddPage
class AddPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2, 3, 4, 5, 6], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_header = tk.Label(self, text="Add Account", font=("Calibri", 14))
        lbl_header.grid(row=0, column=1, sticky='ew')
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
        btn_submit = tk.Button(self, text="Submit", command=lambda: self.add(ent_app, ent_username, ent_email, ent_password, ent_confirmation))
        btn_submit.grid(row=6, column=1, padx=10, pady=5, sticky='ew')
        btn_back = tk.Button(self, text="Back", command=lambda: self.gotomain(ent_app, ent_username, ent_email, ent_password, ent_confirmation))
        btn_back.grid(row=6, column=0, padx=10, pady=5, sticky='ew')
    # Add account Function
    def add(self, ent_app, ent_username, ent_email, ent_password, ent_confirmation):
        global userid
        global key
        global f
        app = ent_app.get().lower()
        username = ent_username.get().lower()
        email = ent_email.get().lower()
        password = ent_password.get()
        confirmation = ent_confirmation.get()
        # Checks entered password and confirmation match
        if password != confirmation:
            messagebox.showerror("Submission Error", "Entered passwords do not match")
        # Checks that no account exists for entered app
        elif len(cur.execute("SELECT * FROM passwords WHERE userid = :userid AND app = :app", {"userid": userid, "app": app}).fetchall()):
            messagebox.showerror("Submission Error", "An account for "+app+" already exists")
        # If no account info exists, insert provided account info
        else:
            cur.execute("INSERT INTO passwords (userid, app, username, email, password) VALUES (:userid, :app, :username, :email, :password)", {"userid": userid, "app": app, "username": username, "email": email, "password": f.encrypt(password.encode(encoding))})
            conn.commit()
            messagebox.showinfo("Submission Complete", "Account info for "+app+" under "+email+" has been entered")
            self.controller.show_frame(MainPage)
            ent_app.delete(0,"end")
            ent_username.delete(0,"end")
            ent_email.delete(0,"end")
            ent_password.delete(0,"end")
            ent_confirmation.delete(0,"end")
    def gotomain(self, ent_app, ent_username, ent_email, ent_password, ent_confirmation):
        self.controller.show_frame(MainPage)
        ent_app.delete(0, "end")
        ent_username.delete(0, "end")
        ent_email.delete(0,"end")
        ent_password.delete(0,"end")
        ent_confirmation.delete(0,"end")
# Create FindPage
class FindPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_header = tk.Label(self, text="Find Password", font=("Calibri", 14))
        lbl_header.grid(row=0, column=1, sticky='ew')
        lbl_app = tk.Label(self, text="Account/App Name:")
        ent_app = tk.Entry(self, width=40)
        lbl_app.grid(row=1,column=0, sticky='e')
        ent_app.grid(row=1,column=1)
        btn_submit = tk.Button(self, text="Submit", command=lambda: self.find(ent_app))
        btn_submit.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
        btn_back = tk.Button(self, text="Back", command=lambda: self.gotomain(ent_app))
        btn_back.grid(row=2, column=0, padx=10, pady=5, sticky='ew')
    # Find password Function
    def find(self, ent_app):
        global userid
        global key
        global f
        app = ent_app.get().lower()
        row = cur.execute("SELECT * FROM passwords WHERE userid = :userid AND app = :app", {"userid": userid, "app": app}).fetchone()
        if len(row) == 0:
            messagebox.showerror("Search Error", "No account for "+app+" found")
        else:
            email = row["email"]
            username = row["username"]
            password = f.decrypt(row["password"]).decode(encoding)
            messagebox.showinfo("Search Results", "Account info for "+app+":\nEmail: "+email+"\nUsername: "+username+"\nPassword: "+password)
            self.controller.show_frame(MainPage)
            ent_app.delete(0,"end")
    def gotomain(self, ent_app):
        self.controller.show_frame(MainPage)
        ent_app.delete(0, "end")

# Create DeletePage
class DeletePage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.grid_rowconfigure([0, 1, 2], weight=1)
        self.grid_columnconfigure([0, 1], weight=1)
        lbl_header = tk.Label(self, text="Delete Account", font=("Calibri", 14))
        lbl_header.grid(row=0, column=1, sticky='ew')
        lbl_app = tk.Label(self, text="Account/App Name:")
        ent_app = tk.Entry(self, width=40)
        lbl_app.grid(row=1,column=0, sticky='e')
        ent_app.grid(row=1,column=1)
        btn_delete = tk.Button(self, text="Delete", command=lambda: self.delete(ent_app))
        btn_delete.grid(row=2, column=1, padx=10, pady=5, sticky='ew')
        btn_main = tk.Button(self, text="Back", command=lambda: self.gotomain(ent_app))
        btn_main.grid(row=2, column=0, padx=10, pady=5, sticky='ew')
    # Delete account Function
    def delete(self, ent_app):
        global userid
        app = ent_app.get().lower()
        if len(cur.execute("SELECT * FROM passwords WHERE userid = :userid AND app = :app", {"userid": userid, "app": app}).fetchone()) == 0:
            messagebox.showerror("Search Error", "No account for "+app+" found")
        else:
            cur.execute("DELETE FROM passwords WHERE userid = :userid AND app = :app", {"userid": userid, "app": app})
            conn.commit()
            messagebox.showinfo("Delete Confirmation", "Account info for "+app+" was successfully deleted")
            self.controller.show_frame(MainPage)
            ent_app.delete(0,"end")
    def gotomain(self, ent_app):
        self.controller.show_frame(MainPage)
        ent_app.delete(0, "end")

app = PassManager()
app.mainloop()