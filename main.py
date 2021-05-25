#### Password Manager - just for coding practice. DO NOT USE, it stores the encryption key in plain txt file
#### if you are looking for a proper Password Manager, use KeePass!

import tkinter as tk
from tkinter import messagebox
from random import choice, randint, shuffle
import pyperclip
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import json
import bcrypt
import os



WINDOW_HEIGHT = 200
WINDOW_WIDTH = 200
LETTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
           'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
           'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
NUMBERS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
SYMBOLS = ['!', '#', '$', '%', '&', '(', ')', '*', '+']
DATABASE_NAME = "data.json"
TOKEN_NAME = "token.txt"
MISSING_PW = "Please enter your Master Password!"

#### PASSWORD GENERATOR
def generate_password():
    password_input.delete(0, tk.END)
    password_list = []

    password_list.extend([choice(LETTERS) for _ in range(randint(5, len(LETTERS) - 1))])
    password_list.extend([choice(NUMBERS) for _ in range(randint(5, len(NUMBERS) - 1))])
    password_list.extend([choice(SYMBOLS) for _ in range(randint(5, len(SYMBOLS) - 1))])

    shuffle(password_list)
    password = "".join(password_list)

    password_input.insert(0, password)

    # copy created password to clipboard for usage
    pyperclip.copy(password)


#### SHOW ENTRIES
# create a search
def search():
    token = user_token_input.get()
    if len(token) < 1:
        messagebox.showwarning(title="Empty", message=MISSING_PW)
    else:
        searched_website = website_input.get()
        check_token()
        try:
            with open(DATABASE_NAME, "r") as password_db:
                # read old data
                data = json.load(password_db)
                password_input.delete(0, tk.END)
                email_input.delete(0, tk.END)
                email_input.insert(0, data[searched_website]["email"])
                password_input.insert(0, decrypt_pw(data[searched_website]["password"].encode(), key).decode())
        except KeyError:
            messagebox.showwarning(title="Not found", message="This website isn't in your database yet.")
        except:
            messagebox.showwarning(title="Wrong PW", message="Wrong Master Password.")


# show a list of available entries
def show_all():
    entry_box.delete(0, tk.END)
    with open(DATABASE_NAME, "r") as database:
        data = json.load(database)
        i = 1
        for key, value in data.items():
            entry_box.insert(i, key)
            i += 1


# select entry with double click and insert into fields
def select_entry(event):
    token = user_token_input.get()
    if len(token) < 1:
        messagebox.showwarning(title="Empty", message=MISSING_PW)
    else:
        check_token()
        selected = entry_box.selection_get()
        website_input.delete(0, tk.END)
        password_input.delete(0, tk.END)
        email_input.delete(0, tk.END)

        try:
            with open(DATABASE_NAME, "r") as password_db:
                # read old data
                data = json.load(password_db)
                website_input.insert(0, selected)
                email_input.insert(0, data[selected]["email"])
                password_input.insert(0, decrypt_pw(data[selected]["password"].encode(), key).decode())
        except:
            messagebox.showwarning(title="Wrong PW", message="Wrong Master Password.")


#### ENCRYPTION
key = None


def encrypt_pw(password: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(password)


def decrypt_pw(token: bytes, key: bytes) -> bytes:
    return Fernet(key).decrypt(token)


def check_token():
    # check if key available, if not create a new one
    global key
    password_provided = user_token_input.get()  # This is input in the form of a string
    password = password_provided.encode()  # Convert to type bytes
    with open(TOKEN_NAME, "r+") as secret:
        secret.seek(0)
        first_character = secret.read(1)
        if not first_character:
            salt = bcrypt.gensalt()
            secret.write(salt.decode())
        else:
            secret.seek(0)
            salt = secret.readline().encode()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once



#### SAVE PASSWORDS & CREATE JSON
def save_password():
    website = website_input.get()
    email = email_input.get()
    password = password_input.get()
    token = user_token_input.get()
    if len(token) < 1:
        messagebox.showwarning(title="Empty", message=MISSING_PW)
    else:
    # encrypt password
        check_token()
        encrypted_password = encrypt_pw(password.encode(), key).decode()

        # create dictionary for json file
        new_entry = {
            website: {
                "email": email,
                "password": encrypted_password,
            }
        }
        if len(website) < 1 or len(password) < 1:
            messagebox.askokcancel(title="Empty", message="Please fill all fields.")
        else:
            try:
                with open(DATABASE_NAME, "r") as password_db:
                    # read old data
                    data = json.load(password_db)

            # if JSON is missing, create a new file
            except FileNotFoundError:
                with open(DATABASE_NAME, "w") as password_db:
                    json.dump(new_entry, password_db, indent=4)
            else:
                # add new entry
                data.update(new_entry)

                with open(DATABASE_NAME, "w") as password_db:
                    # store updated data in json file
                    json.dump(data, password_db, indent=4)

            finally:
                # clean fields
                website_input.delete(0, tk.END)
                password_input.delete(0, tk.END)
                website_input.focus()

#### UI SETUP
window = tk.Tk()
window.title("Password Manager")
window.config(padx=50, pady=50)

# Logo
canvas = tk.Canvas(height=WINDOW_HEIGHT, width=WINDOW_WIDTH)
img_logo = tk.PhotoImage(file="logo.png")
canvas.create_image(WINDOW_HEIGHT / 2, WINDOW_WIDTH / 2, image=img_logo)
canvas.grid(column=1, row=1)

# Website/Email/Password
website_label = tk.Label(text="Website: ")
website_label.grid(column=0, row=2)

website_label = tk.Label(text="Email/Username: ")
website_label.grid(column=0, row=3)

website_label = tk.Label(text="Password: ")
website_label.grid(column=0, row=4)

token_label = tk.Label(text="Your unique Database PW, don't lose it!: ")
token_label.grid(column=0, row=6, columnspan=2)

# User Input fields
website_input = tk.Entry(width=35)
website_input.grid(row=2, column=1)
# start cursor in the website field
website_input.focus()

email_input = tk.Entry(width=35)
email_input.grid(row=3, column=1, columnspan=2, sticky="EW")
# add starting value
email_input.insert(0, "your@email.com")

password_input = tk.Entry(width=21)
password_input.grid(row=4, column=1, sticky="EW")

# user_token
user_token_input = tk.Entry(show="*", width=21)
user_token_input.grid(row=6, column=2, pady=20)

# buttons
generate_button = tk.Button(text="Generate Password", width=14, command=generate_password)
generate_button.grid(row=4, column=2)

add_button = tk.Button(text="Add", width=36, command=save_password)
add_button.grid(row=5, column=1, columnspan=2, pady=20)

search_button = tk.Button(text="Search", width=14, command=search)
search_button.grid(row=2, column=2)

update_button = tk.Button(text="Update List", command=show_all)
update_button.grid(row=0, column=2)

# list of entries
entry_box = tk.Listbox()
# select with double click
entry_box.bind('<Double-1>', select_entry)
entry_box.grid(column=2, row=0, rowspan=3)

#### create tokens.txt and data.json file at first launch
if not os.path.exists(DATABASE_NAME):
    with open(DATABASE_NAME, "w") as password_db:
        # create a new data.json file
        new_file = {}
        json.dump(new_file, password_db, indent=4)

if not os.path.exists(TOKEN_NAME):
    open(TOKEN_NAME, "a").close()

window.mainloop()
