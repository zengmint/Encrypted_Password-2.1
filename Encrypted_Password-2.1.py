import os
import base64
import sqlite3
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk

# Database connection
DATABASE_URL = "sqlite:///passwords.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, execution_options={"future_result": True})
Session = sessionmaker(bind=engine)

# Master Password
MASTER_PASSWORD = None

# SQL Queries
CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS cuentas (
    cuenta TEXT PRIMARY KEY,
    usuario TEXT NOT NULL,
    contrasena_cifrada TEXT NOT NULL,
    iv TEXT NOT NULL,
    salt TEXT NOT NULL
);
"""

INSERT_ACCOUNT = """
INSERT INTO cuentas (cuenta, usuario, contrasena_cifrada, iv, salt) VALUES (:cuenta, :usuario, :contrasena_cifrada, :iv, :salt);
"""

SELECT_ALL_ACCOUNTS = """
SELECT cuenta FROM cuentas;
"""

SELECT_ACCOUNT_DETAILS = """
SELECT usuario, contrasena_cifrada, iv, salt FROM cuentas WHERE cuenta = :account;
"""

UPDATE_ACCOUNT = """
UPDATE cuentas SET usuario = :new_username, contrasena_cifrada = :new_password, iv = :new_iv, salt = :new_salt WHERE cuenta = :account;
"""

# Initialize Database
def initialize_database():
    with engine.connect() as connection:
        connection.execute(text(CREATE_TABLE))

# Fetch all accounts
def get_all_accounts():
    with engine.connect() as connection:
        result = connection.execute(text(SELECT_ALL_ACCOUNTS)).fetchall()
        return [row[0] for row in result]
    
# Fetch account details
def get_account_details(account):
    with engine.connect() as connection:
        result = connection.execute(text(SELECT_ACCOUNT_DETAILS), {"account": account}).fetchone()
        if result and len(result) == 4:  # Verifica que haya 4 columnas
            return result[0], result[1], result[2], result[3]  # usuario, contrasena_cifrada, iv, salt
        return None, None, None, None


# Update account details
def update_account(account, new_username, new_password):
    with engine.connect() as connection:
        connection.execute(
            text(UPDATE_ACCOUNT),
            {
                "new_username": new_username,
                "new_password": new_password,
                "account": account
            }
        )
        connection.commit()  # Explicit commit after update

def generate_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_password(password: str, encryption_key: bytes) -> dict:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    pad_length = 16 - len(password) % 16
    padded_password = password + chr(pad_length) * pad_length
    encrypted_password = encryptor.update(padded_password.encode()) + encryptor.finalize()
    return {
        'ciphertext': base64.b64encode(encrypted_password).decode(),
        'iv': base64.b64encode(iv).decode()
    }

def decrypt_password(encrypted_data: dict, encryption_key: bytes) -> str:
    encrypted_password = base64.b64decode(encrypted_data['ciphertext'])
    iv = base64.b64decode(encrypted_data['iv'])
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
    pad_length = decrypted_password[-1]
    return decrypted_password[:-pad_length].decode()

def master_password_form():
    master_password_window = tk.Tk()
    master_password_window.title("Enter Master Password")
    master_password_window.geometry("350x200+500+200")

    tk.Label(master_password_window, text="Please enter the Master Password:", font=("Arial", 12)).pack(pady=20)

    master_password_entry = tk.Entry(master_password_window, show="*", font=("Arial", 12))
    master_password_entry.pack(pady=10)

    # Al presionar 'Submit', guarda el password ingresado como global y ejecuta el menú principal
    def submit_password():
        global MASTER_PASSWORD
        MASTER_PASSWORD = master_password_entry.get()  # Asigna la entrada como la variable global
        master_password_window.destroy()  # Cierra el formulario de la contraseña
        main_menu()  # Llama al menú principal

    tk.Button(master_password_window, text="Submit", command=submit_password).pack(pady=10)

    master_password_window.mainloop()

# Main Menu
def main_menu():
    root = tk.Tk()
    root.title("Password Manager 2.1")
    root.geometry("350x500+500+200")

    tk.Label(root, text="Encrypted Password 2.1", font=("Arial", 16)).pack(pady=20)

    # Button Icons
    add_icon = ImageTk.PhotoImage(Image.open("add_icon.png").resize((50, 50)))
    consult_icon = ImageTk.PhotoImage(Image.open("consult_icon.png").resize((50, 50)))
    modify_icon = ImageTk.PhotoImage(Image.open("modify_icon.png").resize((50, 50)))
    import_icon = ImageTk.PhotoImage(Image.open("import_icon.png").resize((50, 50)))

    button_width = 80  # Ancho estándar para los botones
    button_height = 60  # Alto estándar para los botones

    tk.Button(root, text="Add Data", image=add_icon, compound="top", command=lambda: [root.destroy(), add_data_form()], width=button_width, height=button_height).pack(pady=10)
    tk.Button(root, text="Consult Data", image=consult_icon, compound="top", command=lambda: [root.destroy(), consult_data_form()], width=button_width, height=button_height).pack(pady=10)
    tk.Button(root, text="Modify Data", image=modify_icon, compound="top", command=lambda: [root.destroy(), modify_data_form()], width=button_width, height=button_height).pack(pady=10)
    tk.Button(root, text="Import CSV", image=import_icon, compound="top", command=import_csv, width=button_width, height=button_height).pack(pady=10)

    tk.Button(root, text="Exit", command=root.destroy).pack(pady=10)

    root.mainloop()

# Add Data Form
def add_data_form():
    form = tk.Tk()
    form.title("Add Data")
    form.geometry("350x500+500+200")

    tk.Label(form, text="Add a New Account", font=("Arial", 14)).pack(pady=10)

    tk.Label(form, text="Account").pack()
    account_entry = tk.Entry(form)
    account_entry.pack(pady=5)

    tk.Label(form, text="Username").pack()
    username_entry = tk.Entry(form)
    username_entry.pack(pady=5)

    tk.Label(form, text="Password").pack()
    password_entry = tk.Entry(form, show="*")
    password_entry.pack(pady=5)

    def add_account():
        account = account_entry.get().strip()
        username = username_entry.get().strip()
        password = password_entry.get().strip()

        if not account or not username or not password:
            messagebox.showwarning("Warning", "All fields are required!")
            return

        salt = os.urandom(16)
        key = generate_key(MASTER_PASSWORD, salt)
        encrypted_data = encrypt_password(password, key)

        try:
            with engine.begin() as connection:  # Use begin() to ensure transactions
                connection.execute(text(INSERT_ACCOUNT), {
                    "cuenta": account,
                    "usuario": username,
                    "contrasena_cifrada": encrypted_data['ciphertext'],
                    "iv": encrypted_data['iv'],
                    "salt": base64.b64encode(salt).decode()
                })
            messagebox.showinfo("Success", "Account added successfully!")
            form.destroy()
            main_menu()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    tk.Button(form, text="Add", command=add_account).pack(pady=10)
    tk.Button(form, text="Back", command=lambda: [form.destroy(), main_menu()]).pack(pady=10)

    form.mainloop()

# Consult Data Form
def consult_data_form():
    form = tk.Tk()
    form.title("Consult Data")
    form.geometry("350x500+500+200")

    tk.Label(form, text="Consult Account Data", font=("Arial", 14)).pack(pady=10)

    accounts = get_all_accounts()

    tk.Label(form, text="Select Account").pack()
    account_combo = ttk.Combobox(form, values=accounts, state="readonly")
    account_combo.pack(pady=5)

    username_var = tk.StringVar()
    password_var = tk.StringVar()

    tk.Label(form, text="Username").pack()
    username_entry = tk.Entry(form, textvariable=username_var, state="disabled")
    username_entry.pack(pady=5)

    tk.Label(form, text="Password").pack()
    password_entry = tk.Entry(form, textvariable=password_var, state="disabled", show="*")
    password_entry.pack(pady=5)

        # Variable to track the visibility of the password
    password_visible = False

    def toggle_password_visibility():
        nonlocal password_visible
        if password_visible:
            password_entry.config(show="*")
            password_visible = False
        else:
            password_entry.config(show="")
            password_visible = True


    def consult_account():
        selected_account = account_combo.get()
        if not selected_account:
            messagebox.showwarning("Warning", "Please select an account!")
            return

        details = get_account_details(selected_account)
        if details[0] is None:  # Verifica si los datos están completos
            messagebox.showerror("Error", "Incomplete or missing account data!")
            return

        username, contrasena_cifrada, iv, salt = details
        salt = base64.b64decode(salt)
        key = generate_key(MASTER_PASSWORD, salt)
        encrypted_data = {
            'ciphertext': contrasena_cifrada,
            'iv': iv
        }
        try:
            decrypted_password = decrypt_password(encrypted_data, key)
            username_var.set(username)
            password_var.set(decrypted_password)
            messagebox.showinfo("Success", f"Account '{selected_account}' loaded successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

    tk.Button(form, text="Consult", command=consult_account).pack(pady=10)
    tk.Button(form, text="Back", command=lambda: [form.destroy(), main_menu()]).pack(pady=10)

    # Button to toggle password visibility
    tk.Button(form, text="Show/Hide Password", command=toggle_password_visibility).pack(pady=10)

    form.mainloop()

# Modify Data Form
def modify_data_form():
    form = tk.Tk()
    form.title("Modify Data")
    form.geometry("350x500+500+200")

    tk.Label(form, text="Modify Account Data", font=("Arial", 14)).pack(pady=10)

    accounts = get_all_accounts()

    tk.Label(form, text="Select Account").pack()
    account_combo = ttk.Combobox(form, values=accounts, state="readonly")
    account_combo.pack(pady=5)

    username_var = tk.StringVar()
    password_var = tk.StringVar()

    tk.Label(form, text="Username").pack()
    username_entry = tk.Entry(form, textvariable=username_var)
    username_entry.pack(pady=5)

    tk.Label(form, text="Password").pack()
    password_entry = tk.Entry(form, textvariable=password_var, show="*")
    password_entry.pack(pady=5)

    def load_account():
        selected_account = account_combo.get()
        if not selected_account:
            messagebox.showwarning("Warning", "Please select an account!")
            return

        details = get_account_details(selected_account)
        if details:
            username, contrasena_cifrada, iv, salt = details
            salt = base64.b64decode(salt)
            key = generate_key(MASTER_PASSWORD, salt)
            encrypted_data = {
                'ciphertext': contrasena_cifrada,
                'iv': iv
            }
            try:
                decrypted_password = decrypt_password(encrypted_data, key)
                username_var.set(username)
                password_var.set(decrypted_password)
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {e}")
        else:
            messagebox.showerror("Error", "Account not found!")

    def modify_account():
        new_username = username_var.get().strip()
        new_password = password_var.get().strip()
        selected_account = account_combo.get()

        if not new_username or not new_password or not selected_account:
            messagebox.showwarning("Warning", "All fields are required!")
            return

        salt = os.urandom(16)
        key = generate_key(MASTER_PASSWORD, salt)
        encrypted_data = encrypt_password(new_password, key)

        try:
            with engine.begin() as connection:
                connection.execute(text(UPDATE_ACCOUNT), {
                    "new_username": new_username,
                    "new_password": encrypted_data['ciphertext'],
                    "new_iv": encrypted_data['iv'],
                    "new_salt": base64.b64encode(salt).decode(),
                    "account": selected_account
                })
            messagebox.showinfo("Success", "Account modified successfully!")
            form.destroy()
            main_menu()
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    tk.Button(form, text="Load Account", command=load_account).pack(pady=10)
    tk.Button(form, text="Modify", command=modify_account).pack(pady=10)
    tk.Button(form, text="Back", command=lambda: [form.destroy(), main_menu()]).pack(pady=10)

    form.mainloop()

# Import data from CSV
def import_csv():
    file_path = filedialog.askopenfilename(
        title="Select CSV File",
        filetypes=[("CSV Files", "*.csv")]
    )
    if not file_path:
        return

    try:
        with open(file_path, "r") as file:
            for line in file:
                # Split line into account, username, and password
                cuenta, usuario, contrasena = line.strip().split(",")

                if not cuenta or not usuario or not contrasena:
                    continue  # Skip incomplete lines

                # Generate salt and encrypt the password
                salt = os.urandom(16)
                key = generate_key(MASTER_PASSWORD, salt)
                encrypted_data = encrypt_password(contrasena, key)

                try:
                    # Insert encrypted data into the database
                    with engine.begin() as connection:  # Ensure transactions
                        connection.execute(text(INSERT_ACCOUNT), {
                            "cuenta": cuenta,
                            "usuario": usuario,
                            "contrasena_cifrada": encrypted_data['ciphertext'],
                            "iv": encrypted_data['iv'],
                            "salt": base64.b64encode(salt).decode()
                        })
                except Exception:
                    pass  # Skip duplicate or invalid entries

        messagebox.showinfo("Import Successful", "Data imported successfully!")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

if __name__ == "__main__":
    initialize_database()
    master_password_form()
