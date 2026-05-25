# 🚀 Ultimate File Upload Vulnerability Scanner

Advanced, multi‑threaded detection tool for file upload vulnerabilities.  
Supports polyglot payloads, CSRF, PUT method, hex editing, obfuscation, and automatic path discovery.

## ✨ Features

- **Polyglot payloads** – Embed PHP into JPEG, PNG, PDF, PHAR while keeping file validity.
- **Multi‑threaded** – Up to 50 concurrent tests.
- **Interactive hex editor** – Manually modify any file before upload.
- **CSRF token extraction** – Automatically fetch and use tokens.
- **PUT method** – Test raw HTTP PUT uploads.
- **Obfuscation** – Case swapping, double extensions, null bytes, trailing spaces.
- **Auto path discovery** – Parses response for uploaded file URLs.
- **JSON reporting** – Detailed results for further analysis.

## 📦 Installation

```bash
git clone https://github.com/yashprj-007/ultimate-upload-scanner.git
cd ultimate-upload-scanner
pip install -r requirements.txt
