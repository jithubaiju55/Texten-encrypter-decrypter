import tkinter as tk
from tkinter import messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

# AES Encryption/Decryption functions
def generate_key_iv():
    key = os.urandom(32)  # 32-byte key for AES-256
    iv = os.urandom(16)   # 16-byte IV for AES
    return key, iv

def encrypt_text(plain_text, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plain_text.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data.hex()  # Convert to hex for easy display

def decrypt_text(encrypted_text, key, iv):
    encrypted_data = bytes.fromhex(encrypted_text)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_text = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_text.decode()

# Application GUI
class TextEncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption App")
        
        # Set up AES key and IV
        self.key, self.iv = generate_key_iv()

        # GUI Components
        self.create_widgets()

    def create_widgets(self):
        # Labels
        self.label = tk.Label(self.root, text="Enter text to encrypt or decrypt", font=("Arial", 14))
        self.label.pack(pady=10)

        # Text Entry Field
        self.text_entry = tk.Entry(self.root, width=50, font=("Arial", 12))
        self.text_entry.pack(pady=10)

        # Encrypt Button
        self.encrypt_button = tk.Button(self.root, text="Encrypt", width=20, command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        # Decrypt Button
        self.decrypt_button = tk.Button(self.root, text="Decrypt", width=20, command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        # Result Label
        self.result_label = tk.Label(self.root, text="Result will appear here", font=("Arial", 12), fg="blue")
        self.result_label.pack(pady=20)

        # Copy Buttons
        self.copy_encrypted_button = tk.Button(self.root, text="Copy Encrypted", width=20, command=self.copy_encrypted)
        self.copy_encrypted_button.pack(pady=5)

        self.copy_decrypted_button = tk.Button(self.root, text="Copy Decrypted", width=20, command=self.copy_decrypted)
        self.copy_decrypted_button.pack(pady=5)

    def encrypt(self):
        # Get the text from the entry field
        plain_text = self.text_entry.get()
        if plain_text:
            encrypted_text = encrypt_text(plain_text, self.key, self.iv)
            self.result_label.config(text=f"Encrypted: {encrypted_text}")
            self.encrypted_text = encrypted_text  # Save encrypted text for later use
        else:
            messagebox.showwarning("Input Error", "Please enter some text to encrypt.")

    def decrypt(self):
        # Get the text from the entry field
        encrypted_text = self.text_entry.get()
        if encrypted_text:
            try:
                decrypted_text = decrypt_text(encrypted_text, self.key, self.iv)
                self.result_label.config(text=f"Decrypted: {decrypted_text}")
                self.decrypted_text = decrypted_text  # Save decrypted text for later use
            except Exception as e:
                messagebox.showerror("Decryption Error", "Invalid encrypted text.")
        else:
            messagebox.showwarning("Input Error", "Please enter encrypted text to decrypt.")

    def copy_encrypted(self):
        try:
            self.root.clipboard_clear()  # Clear the clipboard
            self.root.clipboard_append(self.encrypted_text)  # Append the encrypted text to the clipboard
            self.root.update()  # Update the clipboard
            messagebox.showinfo("Copied", "Encrypted text copied to clipboard!")
        except AttributeError:
            messagebox.showwarning("Error", "No encrypted text to copy.")

    def copy_decrypted(self):
        try:
            self.root.clipboard_clear()  # Clear the clipboard
            self.root.clipboard_append(self.decrypted_text)  # Append the decrypted text to the clipboard
            self.root.update()  # Update the clipboard
            messagebox.showinfo("Copied", "Decrypted text copied to clipboard!")
        except AttributeError:
            messagebox.showwarning("Error", "No decrypted text to copy.")

# Main Program
if __name__ == "__main__":
    root = tk.Tk()
    app = TextEncryptionApp(root)
    root.mainloop()
