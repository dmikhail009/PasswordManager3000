import sqlite3
import time
import base64
import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

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
while True:
    command = None
    valid = ["ADD", "FIND", "LIST", "DELETE", "EXIT"]
    while True:
        command = input("Enter one of the following options:\nADD a new account\nCREATE a new password (\nFIND a password for site/app\nLIST apps/sites in database tied to an email\nDELETE password from database\nEXIT\n\n")
        if command.upper() in valid:
            break
        else:
            print("Please input a command from the listed options")

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
# TODO create GUI for this app: Tkinter or PYsimpleGUI. But will likely need ot learn Tkinter anyways 
# TODO entering wrong password now gives cryptography.fernet.InvalidToken error (when trying to decrypt masterpass) - for useability, find a way to make this a customized error message
# TODO add timer feature to exit program after certain amount of time
# TODO create hash function to generate secure passwords (postpone this)