# AES File Encryption/Decryption Tool
Este é um script Python para criptografar e descriptografar arquivos usando o algoritmo AES-GCM com derivação de chave via PBKDF2-HMAC-SHA256. Ele permite processar recursivamente todos os arquivos dentro de uma pasta, salvando os resultados em outra pasta.

## Funcionalidades
- Criptografia AES-GCM com chave derivada de senha via PBKDF2 (200.000 iterações).
- Suporte a pastas inteiras, mantendo a estrutura de diretórios.
- Interface simples via console para seleção de pastas (usando diálogo gráfico).
- Entrada de senha oculta no terminal.
- Arquivos criptografados recebem extensão .enc.
- Verificação de integridade e autenticação via AES-GCM.
- Compatível com Windows, Linux e macOS (para entrada de senha e seleção de pastas).
## Requisitos
- Python 3.6+
- Biblioteca cryptography
- Biblioteca tkinter (geralmente já incluída no Python padrão)

Instale a biblioteca cryptography via pip, se necessário:
```
pip install cryptography
```
## Como usar
1. Execute o script:
```
python main.py
```
2. Escolha a opção desejada no menu:
- 1 para criptografar arquivos.
- 2 para descriptografar arquivos.

3. Selecione a pasta de entrada (onde estão os arquivos originais ou criptografados).
4. Selecione a pasta de saída (onde os arquivos processados serão salvos).
5. Digite a senha para derivação da chave (a senha não será exibida no terminal).
6. Aguarde o processamento. O script exibirá o status de cada arquivo.
7. Ao final, a pasta de saída será aberta automaticamente.
