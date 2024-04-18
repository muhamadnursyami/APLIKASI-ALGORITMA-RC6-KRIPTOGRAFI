import tkinter as tk
from helpers import *
from tkinter import messagebox

def encrypt_message():
    key = entry_key.get().strip()
    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 characters long")
        return
    
    message = entry_message.get().strip()
    if len(message) < 16:  # Menampilkan pesan kesalahan jika pesan kurang dari 16 karakter
        messagebox.showerror("Error", "Message must be at least 16 characters long")
        return
    
    if len(message) > 16:
        message = message[:16]
    orgi, cipher = encrypt(message, generateKey(key))
    result_orgi.config(state="normal")
    result_orgi.delete("1.0", "end")
    result_orgi.insert("1.0", "Original: " + ' '.join(map(str, orgi)) + "\n")
    result_orgi.config(state="disabled")
    result_cipher.config(state="normal")
    result_cipher.delete("1.0", "end")
    result_cipher.insert("1.0", "Encrypted: " + ' '.join(map(str, cipher)) + "\n")
    result_cipher.config(state="disabled")

    # Save encrypted message to file
    with open("encrypted.txt", "w") as f:
        f.write(' '.join(map(str, cipher)))
        f.write('\n')

def decrypt_message():
    key = entry_key.get().strip()
    if len(key) != 16:
        messagebox.showerror("Error", "Key must be 16 characters long")
        return
    with open("encrypted.txt", "r") as f:
        esentence = f.read().strip()  # Baca nilai enkripsi tanpa memisahkan menjadi bagian-bagian terpisah
    cipher, orgi = decrypt(esentence, generateKey(key))
    result_cipher.config(state="normal")
    result_cipher.delete("1.0", "end")
    result_cipher.insert("1.0", "Encrypted: " + ' '.join(map(str, cipher)) + "\n")
    result_cipher.config(state="disabled")
    result_orgi.config(state="normal")
    result_orgi.delete("1.0", "end")
    result_orgi.insert("1.0", "Decrypted: " + orgi + "\n")  # Menggunakan nilai teks hasil dekripsi langsung
    result_orgi.config(state="disabled")


def generate_key():
    key = entry_key.get().strip()
    if len(key) < 16:
        key = key + " " * (16 - len(key))
    key = key[:16]
    s = generateKey(key)
    result_key.config(state="normal")
    result_key.delete("1.0", "end")
    result_key.insert("1.0", ' '.join(map(str, s)) + "\n")
    result_key.config(state="disabled")

root = tk.Tk()
root.title("RC6 Encryption/Decryption")

frame_key = tk.Frame(root)
frame_key.pack(pady=10)

label_key = tk.Label(frame_key, text="Key:")
label_key.grid(row=0, column=0, padx=(20, 0))
entry_key = tk.Entry(frame_key, width=16)
entry_key.grid(row=0, column=1, padx=(10, 20))
button_key = tk.Button(frame_key, text="Generate Key", command=generate_key)
button_key.grid(row=0, column=2, padx=(10, 20))
result_key = tk.Text(frame_key, height=5, width=50)
result_key.grid(row=1, columnspan=3, padx=(20, 0))
result_key.config(state="disabled")

frame_message = tk.Frame(root)
frame_message.pack(pady=10)

label_message = tk.Label(frame_message, text="Message:")
label_message.grid(row=0, column=0, padx=(20, 0))
entry_message = tk.Entry(frame_message, width=50)
entry_message.grid(row=0, column=1, padx=(10, 20), columnspan=2)
button_encrypt = tk.Button(frame_message, text="Encrypt", command=encrypt_message)
button_encrypt.grid(row=1, column=0, padx=(20, 0))
button_decrypt = tk.Button(frame_message, text="Decrypt", command=decrypt_message)
button_decrypt.grid(row=1, column=2, padx=(10, 0))
result_orgi = tk.Text(frame_message, height=5, width=50)
result_orgi.grid(row=2, column=0, padx=(20, 0), columnspan=3)
result_orgi.config(state="disabled")
result_cipher = tk.Text(frame_message, height=5, width=50)
result_cipher.grid(row=3, column=0, padx=(20, 0), columnspan=3)
result_cipher.config(state="disabled")

root.mainloop()