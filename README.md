# JuypterSSH

Expose any Jupyter **kernel** as a lightning-fast **SSH / SFTP** endpoint – no browser required.

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue"/>
  <img src="https://img.shields.io/badge/License-MIT-green"/>
  <img src="https://img.shields.io/badge/Status-Alpha-orange"/>
</p>

---

## ✨ Features
* **Interactive shell** – feel at home with a real Bash prompt backed by the notebook kernel.
* **File transfers** – full SFTP & SCP support via the Jupyter Contents API.
* **Zero-config auth** – ships open (no password).  Plug in your own auth backend easily.
* **Static host key** – stable fingerprint, no more *host key changed* warnings.
* **Warm start** – pre-spawns a kernel so the first connection is instant.
* **Emoji-powered UX** – friendly banners & progress spinners (disable with `JUPYTERSSH_UI=0`).

---

## 🚀 Quick-start
```bash
# 1. Clone & install deps
pip install -r requirements.txt

# 2. Launch the bridge (replace URL with yours)
python juypter_ssh_server.py \
    --jupyter-url "https://my.server/lab?token=SECRET" \
    --port 2222

# 3. Connect – no password required
ssh anyuser@server -p 2222

# 4. Transfer files
scp -P 2222 data.csv anyuser@server:/workspace/
```

Environment variables:
* `JUYPTERSSH_DEBUG=1` – verbose logging.
* `JUPYTERSSH_UI=0`   – disable Rich spinners.

### 🔗  Getting your Kaggle Jupyter URL
If your notebook runs on **Kaggle**:
1. Open the notebook as usual.  
2. In the top menu bar choose **Run ▸ Kaggle Jupyter Server**.  
3. A dialog appears – click **"VS Code Compatible URL"** and copy the link (it already contains the token).  
4. Pass that link to `--jupyter-url` when starting JuypterSSH.

Example:
```bash
python juypter_ssh_server.py --jupyter-url "https://kkb-production.jupyter-proxy.kaggle.net/k/12345abcdef/XYZTOKEN/proxy" --port 2222
```

---

## 🛠️  Installation
PyPI release **coming soon** – for now install from source:
```bash
git clone https://github.com/yaelliethy/JuypterSSH.git
cd JuypterSSH
pip install -r requirements.txt
```
Then launch with:
```bash
python juypter_ssh_server.py --jupyter-url <YOUR_URL>
```

Requires **Python 3.9+** and a reachable Jupyter server (local or remote).

---

## 📝  Documentation
Full technical deep-dive in [`Technical.md`](Technical.md).

Topics covered:
* Component architecture
* Performance tricks (C PTY reader, batching, stdbuf)
* Security model & hardening tips
* Extending auth, shell types, file streaming

---

## 🔒  Security notes
JuypterSSH defaults to:
* **`none` auth** (open access).  Override `SSHHandler` methods to enforce keys/passwords.
* **Static embedded RSA host key** (2048-bit).  Regenerate before production:
  ```bash
  ssh-keygen -t rsa -b 2048 -m PEM -C JuypterSSH -f hostkey.pem
  ```
  and paste into `ssh_server.py`.

---

## 🤔  FAQ
**Q:** *Does it work on Windows?*  
A: Server – yes (WSL recommended).  Client – any OpenSSH/SFTP.

**Q:** *Multiple users?*  
A: Each SSH connection gets its **own** Jupyter session/kernel; add auth to map users→tokens.

**Q:** *Why not talk ZeroMQ directly?*  
A: Simplicity & compatibility with hosted Jupyter (Binder, Kaggle) that only expose REST/WS.

---

## ❤️  Contributing
PRs & issues welcome!  See `Technical.md` and `CONTRIBUTING.md`

---

## ☕  Support

To support this project (and my studies) please consider buying a coffee:


[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-%23FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black)](https://www.buymeacoffee.com/yaelliethy)
---
## 📜  License
MIT © 2024 – JuypterSSH authors 
