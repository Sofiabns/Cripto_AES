"""
Cripto_AES — Ferramenta de criptografia/descriptografia de arquivos com AES-256-GCM.

Algoritmo : AES-256-GCM  (autenticado, detecta adulteração)
KDF       : PBKDF2-HMAC-SHA256 (200.000 iterações)
Interface : console interativo + diálogo gráfico de seleção de pasta (tkinter)

Uso:
    python main.py
"""

import getpass
import logging
import os
import sys
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path
from tkinter import filedialog
from typing import Literal

import secrets
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---------------------------------------------------------------------------
# Constantes criptográficas
# ---------------------------------------------------------------------------
MAGIC = b"ENCv1"          # Assinatura de arquivo criptografado
SALT_SIZE = 16             # bytes
NONCE_SIZE = 12            # bytes (96 bits — padrão recomendado para AES-GCM)
KDF_ITERS = 200_000        # iterações PBKDF2
KEY_SIZE = 32              # bytes → AES-256

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)
logger = logging.getLogger(__name__)

Mode = Literal["encrypt", "decrypt"]


# ---------------------------------------------------------------------------
# Resultado de processamento
# ---------------------------------------------------------------------------
@dataclass
class ProcessResult:
    success: int = 0
    skipped: int = 0
    errors: int = 0
    error_files: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Criptografia
# ---------------------------------------------------------------------------

def derive_key(password: bytes, salt: bytes) -> bytes:
    """Deriva uma chave AES-256 a partir de uma senha e salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=KDF_ITERS,
        backend=default_backend(),
    )
    return kdf.derive(password)


def encrypt_file(in_path: Path, out_path: Path, password: str) -> None:
    """
    Criptografa ``in_path`` com AES-256-GCM e salva em ``out_path``.

    Formato do arquivo de saída:
        MAGIC (5B) | salt (16B) | nonce (12B) | ciphertext+tag

    Raises
    ------
    OSError
        Se não for possível ler o arquivo de entrada ou escrever o de saída.
    """
    plaintext = in_path.read_bytes()

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    key = derive_key(password.encode("utf-8"), salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(MAGIC + salt + nonce + ciphertext)


def decrypt_file(in_path: Path, out_path: Path, password: str) -> None:
    """
    Descriptografa ``in_path`` e salva o conteúdo original em ``out_path``.

    Raises
    ------
    ValueError
        Se o arquivo não tiver a assinatura esperada (MAGIC).
    InvalidTag
        Se a senha estiver errada ou o arquivo tiver sido adulterado.
    OSError
        Se não for possível ler/escrever os arquivos.
    """
    data = in_path.read_bytes()

    if not data.startswith(MAGIC):
        raise ValueError(f"Arquivo não possui assinatura válida: {in_path.name}")

    offset = len(MAGIC)
    salt = data[offset : offset + SALT_SIZE]
    offset += SALT_SIZE
    nonce = data[offset : offset + NONCE_SIZE]
    offset += NONCE_SIZE
    ciphertext = data[offset:]

    key = derive_key(password.encode("utf-8"), salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)  # lança InvalidTag se falhar

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(plaintext)


# ---------------------------------------------------------------------------
# Processamento de pastas
# ---------------------------------------------------------------------------

def process_folder(
    input_dir: Path,
    output_dir: Path,
    password: str,
    mode: Mode,
) -> ProcessResult:
    """
    Percorre ``input_dir`` recursivamente e aplica criptografia ou descriptografia.

    Parâmetros
    ----------
    input_dir  : pasta de entrada
    output_dir : pasta de saída (criada automaticamente se não existir)
    password   : senha para derivação da chave
    mode       : ``"encrypt"`` ou ``"decrypt"``

    Retorna
    -------
    ProcessResult com contadores de sucesso, ignorados e erros.
    """
    result = ProcessResult()
    all_files = [p for p in input_dir.rglob("*") if p.is_file()]

    if not all_files:
        logger.warning("[AVISO] Nenhum arquivo encontrado em: %s", input_dir)
        return result

    total = len(all_files)
    logger.info("")

    for idx, in_path in enumerate(all_files, start=1):
        rel = in_path.relative_to(input_dir)
        prefix = f"[{idx}/{total}]"

        if mode == "encrypt":
            out_path = output_dir / (str(rel) + ".enc")
            try:
                encrypt_file(in_path, out_path, password)
                logger.info("%s [OK] Criptografado: %s", prefix, rel)
                result.success += 1
            except OSError as exc:
                logger.error("%s [ERRO] %s → %s", prefix, rel, exc)
                result.errors += 1
                result.error_files.append(str(rel))

        else:  # decrypt
            if in_path.suffix != ".enc":
                logger.info("%s [IGNORADO] Sem extensão .enc: %s", prefix, rel)
                result.skipped += 1
                continue

            out_path = output_dir / Path(str(rel)).with_suffix("")
            try:
                decrypt_file(in_path, out_path, password)
                logger.info("%s [OK] Descriptografado: %s", prefix, rel)
                result.success += 1
            except ValueError as exc:
                logger.error("%s [ERRO] %s", prefix, exc)
                result.errors += 1
                result.error_files.append(str(rel))
            except InvalidTag:
                logger.error(
                    "%s [ERRO] Senha incorreta ou arquivo corrompido: %s", prefix, rel
                )
                result.errors += 1
                result.error_files.append(str(rel))
            except OSError as exc:
                logger.error("%s [ERRO] %s → %s", prefix, rel, exc)
                result.errors += 1
                result.error_files.append(str(rel))

    return result


# ---------------------------------------------------------------------------
# Interface — seleção de pasta
# ---------------------------------------------------------------------------

def escolher_pasta(titulo: str) -> Path | None:
    """Abre um diálogo gráfico para seleção de pasta. Retorna None se cancelado."""
    root = tk.Tk()
    root.attributes("-topmost", True)
    root.withdraw()
    pasta = filedialog.askdirectory(title=titulo, mustexist=True)
    root.destroy()
    return Path(pasta) if pasta else None


# ---------------------------------------------------------------------------
# Interface — entrada de senha oculta
# ---------------------------------------------------------------------------

def input_senha(prompt: str = "Digite a senha: ") -> str:
    """
    Lê a senha sem exibir caracteres no terminal.
    Usa ``msvcrt`` no Windows (com eco de asteriscos) e ``getpass`` nos demais.
    """
    try:
        import msvcrt  # Windows only

        print(prompt, end="", flush=True)
        senha = ""
        while True:
            ch = msvcrt.getch()
            if ch in {b"\r", b"\n"}:
                print()
                break
            elif ch == b"\x08":  # Backspace
                if senha:
                    senha = senha[:-1]
                    sys.stdout.write("\b \b")
                    sys.stdout.flush()
            elif ch == b"\x03":  # Ctrl+C
                raise KeyboardInterrupt
            else:
                try:
                    c = ch.decode("utf-8")
                except UnicodeDecodeError:
                    continue
                senha += c
                sys.stdout.write("*")
                sys.stdout.flush()
        return senha

    except ImportError:
        return getpass.getpass(prompt)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    print("=" * 42)
    print("     CRIPTO AES — Criptografia de Arquivos")
    print("=" * 42)
    print("  1  Criptografar arquivos")
    print("  2  Descriptografar arquivos")
    print("  0  Sair")
    print()

    escolha = input("Escolha uma opção: ").strip()

    if escolha == "0":
        print("Saindo...")
        return

    if escolha not in {"1", "2"}:
        print("[ERRO] Opção inválida.")
        return

    modo: Mode = "encrypt" if escolha == "1" else "decrypt"
    label_modo = "criptografar" if modo == "encrypt" else "descriptografar"

    print(f"\nSelecione a pasta de ENTRADA (arquivos a {label_modo})...")
    pasta_entrada = escolher_pasta("Selecione a pasta de entrada")
    if not pasta_entrada:
        print("Nenhuma pasta selecionada. Saindo...")
        return

    print("Selecione a pasta de SAÍDA (onde os arquivos processados serão salvos)...")
    pasta_saida = escolher_pasta("Selecione a pasta de saída")
    if not pasta_saida:
        print("Nenhuma pasta selecionada. Saindo...")
        return

    if pasta_entrada == pasta_saida:
        print("[ERRO] As pastas de entrada e saída não podem ser as mesmas.")
        return

    senha = input_senha("\nDigite a senha: ")
    if not senha:
        print("[ERRO] A senha não pode estar vazia.")
        return

    # Confirmação de senha apenas na criptografia
    if modo == "encrypt":
        senha2 = input_senha("Confirme a senha: ")
        if senha != senha2:
            print("[ERRO] As senhas não coincidem.")
            return

    print(f"\nProcessando '{pasta_entrada}' → '{pasta_saida}'...")
    result = process_folder(pasta_entrada, pasta_saida, senha, modo)

    # Resumo
    print()
    print("=" * 42)
    print(f"  ✔  Sucesso  : {result.success}")
    if result.skipped:
        print(f"  –  Ignorados: {result.skipped}")
    if result.errors:
        print(f"  ✘  Erros    : {result.errors}")
        for f in result.error_files:
            print(f"       • {f}")
    print("=" * 42)
    print("  Operação concluída!")
    print()

    # Abre a pasta de saída (Windows / macOS / Linux)
    try:
        import subprocess, platform
        system = platform.system()
        if system == "Windows":
            os.startfile(pasta_saida)
        elif system == "Darwin":
            subprocess.Popen(["open", pasta_saida])
        else:
            subprocess.Popen(["xdg-open", pasta_saida])
    except Exception as exc:
        logger.debug("Não foi possível abrir a pasta automaticamente: %s", exc)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperação cancelada pelo usuário.")
        sys.exit(0)
