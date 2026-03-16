# Cripto_AES 🔐

> Ferramenta de linha de comando para **criptografar e descriptografar arquivos e pastas inteiras** com AES-256-GCM, derivação de chave via PBKDF2-HMAC-SHA256 e interface gráfica de seleção de pastas.

---

## Índice

- [Sobre o projeto](#sobre-o-projeto)
- [Segurança](#segurança)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Como usar](#como-usar)
- [Formato do arquivo criptografado](#formato-do-arquivo-criptografado)
- [Estrutura do projeto](#estrutura-do-projeto)
- [Próximas melhorias](#próximas-melhorias)
- [Licença](#licença)

---

## Sobre o projeto

O **Cripto_AES** é uma ferramenta Python focada em **privacidade local**. Com ela você seleciona uma pasta de entrada, uma pasta de saída e digita uma senha — o programa cuida do restante, processando todos os arquivos recursivamente e preservando a estrutura de diretórios.

Casos de uso típicos: backup criptografado em nuvem, proteção de documentos sensíveis, envio seguro de arquivos por canais não confiáveis.

---

## Segurança

| Componente | Escolha | Por quê |
|------------|---------|---------|
| Cifra | AES-256-GCM | Criptografia autenticada — detecta adulteração e garante integridade |
| KDF | PBKDF2-HMAC-SHA256 | Resistente a ataques de força bruta com 200.000 iterações |
| Salt | 16 bytes aleatórios | Garante que a mesma senha gere chaves diferentes em cada arquivo |
| Nonce | 12 bytes aleatórios | Garante que o mesmo conteúdo gere ciphertexts diferentes |
| Assinatura | `ENCv1` (5 bytes) | Identifica arquivos criptografados e versão do formato |

> **Atenção:** A segurança depende diretamente da força da senha escolhida. Use senhas longas e únicas.

---

## Pré-requisitos

- Python **3.11** ou superior
- `tkinter` (já incluso na instalação padrão do Python)

---

## Instalação

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/Cripto_AES.git
cd Cripto_AES

# 2. (Opcional) Crie um ambiente virtual
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# 3. Instale a dependência
pip install -r requirements.txt
```

---

## Como usar

```bash
python main.py
```

**Passo a passo:**

1. Escolha `1` para **criptografar** ou `2` para **descriptografar**
2. Selecione a **pasta de entrada** no diálogo gráfico
3. Selecione a **pasta de saída** (deve ser diferente da entrada)
4. Digite a senha — os caracteres não são exibidos no terminal
5. Na criptografia, confirme a senha para evitar erros de digitação
6. Aguarde o processamento; ao final um resumo é exibido e a pasta de saída é aberta automaticamente

**Saída no terminal:**

```
==========================================
     CRIPTO AES — Criptografia de Arquivos
==========================================
  1  Criptografar arquivos
  2  Descriptografar arquivos
  0  Sair

Escolha uma opção: 1

[1/3] [OK] Criptografado: documentos/relatorio.pdf
[2/3] [OK] Criptografado: documentos/planilha.xlsx
[3/3] [OK] Criptografado: fotos/imagem.jpg

==========================================
  ✔  Sucesso  : 3
==========================================
  Operação concluída!
```

---

## Formato do arquivo criptografado

Cada arquivo `.enc` gerado possui a seguinte estrutura binária:

```
┌─────────────┬──────────────┬──────────────┬──────────────────────────┐
│  MAGIC      │  salt        │  nonce       │  ciphertext + auth tag   │
│  5 bytes    │  16 bytes    │  12 bytes    │  N + 16 bytes            │
│  "ENCv1"    │  aleatório   │  aleatório   │  AES-256-GCM             │
└─────────────┴──────────────┴──────────────┴──────────────────────────┘
```

- O **salt** é único por arquivo, garantindo que arquivos idênticos com a mesma senha produzam ciphertexts distintos
- O **auth tag** de 16 bytes (embutido no ciphertext pelo AES-GCM) garante que qualquer adulteração seja detectada na descriptografia

---

## Estrutura do projeto

```
Cripto_AES/
├── main.py           # Lógica de criptografia + interface console
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Próximas melhorias

- [ ] Interface gráfica completa com Tkinter (barra de progresso, log em tempo real)
- [ ] Suporte a criptografia de arquivo único (além de pastas)
- [ ] Opção `--in-place` para substituir os originais após criptografar
- [ ] Exportação de relatório de processamento em `.txt`
- [ ] Testes automatizados com `pytest`
- [ ] Empacotamento em executável standalone com `PyInstaller`

---

## Licença

Distribuído sob a licença **MIT**. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
