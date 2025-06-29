# JuypterSSH – Technical Documentation

*Version: 1.0*

---

## Table of Contents
1. Overview  
2. High-level Architecture  
3. Component Details  
   3.1 `jupyter_backend.py`  
   3.2 `ssh_server.py`  
   3.3 `sftp_server.py`  
4. Execution Flow  
5. Performance Optimisations  
6. Security Considerations  
7. Extending & Customising  
8. CLI Usage  
9. Development / Test Notes

---

## 1. Overview
JuypterSSH exposes a **Jupyter kernel** as a fully-featured **SSH / SFTP** endpoint.  
End-users can:
* Open an interactive shell: `ssh user@host -p 2222`  
* Copy files: `scp foo.txt user@host:/workspace/`  
* Mount via SFTP‐aware editors.

Internally, every SSH connection is bridged to **its own Jupyter session / kernel**.  The bridge is bi-directional:
* **Outbound** (user → kernel) keystrokes are forwarded into a Bash process running inside the kernel.
* **Inbound** (kernel → user) PTY bytes are streamed back via WebSocket → Paramiko channel.

All heavy-lifting (auth, SFTP, PTY muxing) happens in Python; no custom C except a tiny optional PTY reader compiled inside the kernel for speed.

---

## 2. High-level Architecture
```mermaid
flowchart TD;
    Client[SSH / SFTP client]
    subgraph Server (JuypterSSH)
        direction TB
        A[Paramiko Transport] -->|channels| B[SSHHandler]
        B <-->|queue| C[JupyterBackend]
    end
    subgraph JupyterHost
        direction TB
        K[Jupyter REST API]\n+ WebSocket
        JupyterKernel[Bash in PTY]\n(running inside kernel)
    end
    Client -->|TCP 2222| A
    C  -->|HTTP / WS| K
    K  -->|stdin/out| JupyterKernel
```

---

## 3. Component Details
### 3.1 `jupyter_backend.py`
Central high-level wrapper around Jupyter REST + WebSocket APIs.

Key responsibilities:
* **URL parsing** — supports `/lab?token=...`, Kaggle proxy paths, etc.
* **Session / Kernel lifecycle** — `_ensure_session_and_kernel()` lazily creates a notebook + kernel per backend instance.
* **WebSocket management** — persistent connection, background reader that demultiplexes frames.
* **Code-execution helpers**  
  * `execute_code*` – fire & forget, wait for results  
  * `stream_code_async` – push output chunks to callback
* **Interactive Shell helpers**  
  * `start_interactive_shell()` initialises a Bash PTY inside the kernel, starts ultra-fast C reader, and registers a subscriber for streaming.
  * `send_input_to_shell()` feeds raw bytes into master fd.
* **Contents API subset** for SFTP (list/save/delete/rename).

Performance tweaks implemented:  
* WebSocket text batching (5 ms window).  
* C reader (`libpty_reader.so`) – 64 KiB buffer, 20 µs select timeout.  
* All Bash instances wrapped with `stdbuf -oL -eL` ⇒ line-buffered.

### 3.2 `ssh_server.py`
Implements the actual SSH server.

* `JuypterSSHServer` – socket listener; creates **one new `JupyterBackend` per connection** (or hands out a pre-warmed instance).
* Deterministic RSA host key embedded in PEM string ⇒ stable fingerprint `SHA256:2kA7cA/9Qxt3…` (no "host key changed" errors).
* **Auth** — `none` auth accepted; password disabled.
* **SSHHandler** – per-channel logic  
  * PTY requests → resize Jupyter PTY  
  * `exec` → synchronous execution via `execute_in_shell()`  
  * Shell channel → bridges to interactive PTY.
* **Micro-batching** — outbound kernel text queued & flushed every 0.1 ms (user changed to 0.0001) to minimise packet count.

### 3.3 `sftp_server.py`
Paramiko `SFTPServerInterface` implementation backed by the Jupyter Contents API.

* `JupyterSFTPHandle` — in-memory `BytesIO` buffer; flushes on close; honours `O_TRUNC`, `O_APPEND`, etc.
* `JupyterSFTPServer` — implements `list_folder`, `stat`, `open`, plus write ops (`remove`, `rename`, `mkdir`, …).  Paths are sanitised against `..` traversal.

---

## 4. Execution Flow
1. **Startup**  
   `juypter_ssh_server.py` → parses CLI, starts `JuypterSSHServer`, spins a *warm* backend (kernel) with Rich spinner.
2. **Client connects** (TCP 2222) → Paramiko handshake → `none` auth accepted.
3. **Shell channel**  
   * Server ensures PTY Bash exists in kernel.  
   * `_reader_loop` inside kernel pushes stdout to backend → `_out_cb` → micro-batch queue → `channel.send()` (CRLF converted).
4. **User input**  
   `channel.recv()` bytes forwarded into `send_input_to_shell()` → `os.write(master_fd)`.
5. **Termination**  
   Typing `exit` kills Bash → kernel prints sentinel `[[BASH_EXITED]]` → bridge sees it, flushes queue, closes channel.

---

## 5. Performance Optimisations Implemented
| Area | Optimisation | Gain |
|------|--------------|------|
| Kernel → SSH | C reader, 64 KiB buf, 20 µs poll | ~4× throughput |
| SSH → Kernel | Micro-batch queue, 0.1 ms flush | ~2× fewer packets |
| Bash buffering | `stdbuf -oL` | Instant echo |
| Warm kernel | pre-spawned on server start | Removes 1-2 s first-connect latency |
| No JSON parsing for SFTP | direct bytes | negligible but clean |

Still on roadmap: binary WS frames, ZeroMQ transport, Go/Rust bridge.

---

## 6. Security Considerations
* **Host Key** – static but *private*; regenerate and embed your own before releasing.
* **Unauthenticated access** – good for private deployments; add your own `check_auth_publickey` if needed.
* **Path sanitisation** – SFTP rejects `..` traversals; Contents API enforces notebook root.
* **Kernel Isolation** – each SSH connection → its own kernel session (memory/CPU enforced by Jupyter hub).

---

## 7. Extending & Customising
* **Auth plugins** – subclass `SSHHandler`, implement `check_auth_publickey` + token lookup.
* **Different shells** – change `['stdbuf', …, '/bin/zsh', '-i']` lines.
* **Transfer huge files** – switch SFTP handle to stream via HTTP range.
* **Metrics** – hook `_out_cb` + `send_input_to_shell` for Prometheus counters.

---

## 8. CLI Usage
```bash
# Install deps
pip install -r requirements.txt

# Run server
python juypter_ssh_server.py --jupyter-url https://host/lab?token=XYZ --port 2222

# Connect (no password)
ssh user@server -p 2222

# Copy file
scp -P 2222 my.py user@server:/workspace/
```
Env vars:
* `JUYPTERSSH_DEBUG=1` – verbose logs.
* `JUPYTERSSH_UI=0` – disable Rich spinner.

---

## 9. Development / Test Notes
* `pytest` tests live in `test_jupyter_url.py` for URL parsing.
* Use `fake_ssh_server.py` legacy entry-point; prints deprecation banner.
* To regenerate host key: `ssh-keygen -t rsa -b 2048 -m PEM -C JuypterSSH -f hostkey.pem` and embed PEM.

---

*End of document.* 