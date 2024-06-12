# app.py
from flask import Flask, request, render_template
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import base64

app = Flask(__name__)

# Function to pad plaintext for AES block size
def pad(data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Function to unpad plaintext after AES decryption
def unpad(data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    unpadded_data = unpadder.update(data) + unpadder.finalize()
    return unpadded_data

# Encrypt text using AES-CBC
def encrypt_aes_cbc(key, plaintext):
    iv = os.urandom(16)  # Generate a random 16-byte IV
    key = key.encode('utf-8')[:16]  # Ensure the key is 16 bytes

    # Pad the plaintext to be multiple of block size
    padded_plaintext = pad(plaintext.encode('utf-8'))

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # Return the IV and ciphertext encoded as base64
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Decrypt text using AES-CBC
def decrypt_aes_cbc(key, encrypted_text):
    try:
        encrypted_bytes = base64.b64decode(encrypted_text.encode('utf-8'))
        iv = encrypted_bytes[:16]  # Extract the IV
        ciphertext = encrypted_bytes[16:]  # Extract the ciphertext

        key = key.encode('utf-8')[:16]  # Ensure the key is 16 bytes

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        plaintext = unpad(padded_plaintext)
        return plaintext.decode('utf-8')
    except Exception as e:
        return f"Error: {str(e)}"

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        text = request.form["text"]
        key = request.form["key"]
        action = request.form["action"]

        if action == "encrypt":
            result = encrypt_aes_cbc(key, text)
        elif action == "decrypt":
            result = decrypt_aes_cbc(key, text)

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
