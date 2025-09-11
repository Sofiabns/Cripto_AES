import os
import getpass
import secrets
import sys
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

MAGIC = b'ENCv1'
SALT_SIZE = 16
NONCE_SIZE = 12
KDF_ITERS = 200_000
KEY_SIZE = 32

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend()
    )
    return kdf.derive(password)

def encrypt_file(in_path, out_path, password):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    salt = secrets.token_bytes(SALT_SIZE)
    key = derive_key(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(MAGIC + salt + nonce + ciphertext)

def decrypt_file(in_path, out_path, password):
    with open(in_path, 'rb') as f:
        header = f.read(len(MAGIC))
        if header != MAGIC:
            print(f"[ERRO] Arquivo não está criptografado: {in_path}")
            return
        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        ciphertext = f.read()

    key = derive_key(password.encode('utf-8'), salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        print(f"[ERRO] Senha incorreta ou arquivo corrompido: {in_path}")
        return

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'wb') as f:
        f.write(plaintext)

def process_folder(input_dir, output_dir, password, mode):
    for root, _, files in os.walk(input_dir):
        for fname in files:
            in_path = os.path.join(root, fname)
            rel = os.path.relpath(in_path, input_dir)

            if mode == "encrypt":
                out_path = os.path.join(output_dir, rel) + ".enc"
                encrypt_file(in_path, out_path, password)
                print(f"[OK] Criptografado: {rel}")
            else:
                if not fname.endswith(".enc"):
                    print(f"[SKIP] Ignorando (não tem .enc): {rel}")
                    continue
                out_path = os.path.join(output_dir, rel[:-4])
                decrypt_file(in_path, out_path, password)
                print(f"[OK] Descriptografado: {rel}")

def escolher_pasta(titulo):
    root = tk.Tk()
    root.attributes('-topmost', True)  
    root.withdraw()  
    pasta = filedialog.askdirectory(title=titulo, mustexist=True)
    root.destroy()
    return pasta
''

def input_senha(prompt="Digite a senha: "):
    try:
        
        import msvcrt
        print(prompt, end='', flush=True)
        senha = ''
        while True:
            ch = msvcrt.getch()
            if ch in {b'\r', b'\n'}:  
                print()
                break
            elif ch == b'\x08':  
                if len(senha) > 0:
                    senha = senha[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif ch == b'\x03':  
                raise KeyboardInterrupt
            else:
                try:
                    c = ch.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                senha += c
                sys.stdout.write('*')
                sys.stdout.flush()
        return senha
    except ImportError:
        
        return getpass.getpass(prompt)
    
def main():
    print("==== CONSOLE DE CRIPTOGRAFIA AES ====")
    print("1 - Criptografar arquivos")
    print("2 - Descriptografar arquivos")
    escolha = input("Escolha uma opção: ").strip()

    if escolha not in ["1", "2"]:
        print("Opção inválida!")
        return

    modo = "encrypt" if escolha == "1" else "decrypt"

    print("\nSelecione a pasta de ENTRADA...")
    pasta_entrada = escolher_pasta("Selecione a pasta de entrada")
    if not pasta_entrada:
        print("Nenhuma pasta selecionada. Saindo...")
        return

    print("\nSelecione a pasta de SAÍDA...")
    pasta_saida = escolher_pasta("Selecione a pasta de saída")
    if not pasta_saida:
        print("Nenhuma pasta selecionada. Saindo...")
        return

    senha = input_senha("\nDigite a senha: ")


    process_folder(pasta_entrada, pasta_saida, senha, modo)
    print("\n[FINALIZADO] Operação concluída!")

    
    try:
        os.startfile(pasta_saida)
    except Exception as e:
        print(f"[AVISO] Não foi possível abrir a pasta automaticamente: {e}")


if __name__ == "__main__":
    main()
