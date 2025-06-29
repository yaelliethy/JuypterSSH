import logging
import os
import socket
import threading
import time
from typing import Optional
import json
import queue

import paramiko

from jupyter_backend import JupyterBackend, JupyterBackendError
from sftp_server import JupyterSFTPServer  # type: ignore

log_level = logging.INFO if os.getenv("JUYPTERSSH_DEBUG") == "1" else logging.WARNING
logging.basicConfig(level=log_level, format="%(levelname)s %(name)s - %(message)s")

LOGGER = logging.getLogger(__name__)


class SSHHandler(paramiko.ServerInterface):
    """Paramiko ServerInterface implementation for JuypterSSH server."""

    def __init__(self, backend: JupyterBackend):
        self.backend = backend
        self.shell_event = threading.Event()
        self.exec_event = threading.Event()

    # ----------------------- AUTH -----------------------------
    def check_auth_password(self, username: str, password: str):
        # Password auth disabled - use check_auth_none instead
        return paramiko.AUTH_FAILED  # type: ignore[attr-defined]

    def check_auth_none(self, username: str):
        # Accept any user without authentication
        LOGGER.info("Accepted no-auth for user=%s", username)
        return paramiko.AUTH_SUCCESSFUL  # type: ignore[attr-defined]

    def get_allowed_auths(self, username):
        return "none"

    # --------------------- CHANNELS ---------------------------
    def check_channel_request(self, channel_type, chanid):
        if channel_type == "session":
            return paramiko.OPEN_SUCCEEDED  # type: ignore[attr-defined]
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED  # type: ignore[attr-defined]

    def check_channel_shell_request(self, channel):
        """Bridge the SSH client directly to a persistent bash running inside the Jupyter kernel."""

        LOGGER.info("Shell request received – activating interactive bridge")

        def shell_handler():
            try:
                # ------------------------------------------------------------------
                # 1) Kick-off / verify remote interactive shell & start streaming output
                # ------------------------------------------------------------------
                _send_q: "queue.Queue[Optional[str]]" = queue.Queue()

                def _sender_loop():
                    buff = []
                    last_flush = time.time()
                    while True:
                        try:
                            chunk = _send_q.get(timeout=0.05)
                            if chunk is None:
                                break
                            buff.append(chunk)
                        except queue.Empty:
                            pass

                        now = time.time()
                        if buff and (now - last_flush > 0.0001):  # 5 ms batch window
                            data = ''.join(buff)
                            buff.clear()
                            channel.send(data.encode())
                            last_flush = now

                    # flush remaining
                    if buff:
                        channel.send(''.join(buff).encode())

                threading.Thread(target=_sender_loop, daemon=True).start()

                def _out_cb(txt: str):
                    if not txt:
                        return

                    if '[[BASH_EXITED]]' in txt:
                        cleaned = txt.replace('[[BASH_EXITED]]', '')
                        if cleaned:
                            _send_q.put(cleaned.replace('\n', '\r\n'))
                        _send_q.put(None)  # signal sender loop to finish
                        channel.close()
                        self.shell_event.set()
                        return

                    _send_q.put(txt.replace('\n', '\r\n'))

                self.backend.start_interactive_shell(_out_cb)

                # Send a small greeting so the user sees *something* immediately.
                # channel.send(b"\xf0\x9f\x94\x97 JuypterSSH | Connected to Jupyter kernel bash \xf0\x9f\x8e\x89\r\n")

                # ------------------------------------------------------------------
                # 2) Pump data coming *from* the SSH client into the remote PTY.
                # ------------------------------------------------------------------
                while True:
                    data = channel.recv(1024)
                    if not data:
                        break  # Client disconnected.

                    # Forward raw bytes as-is (decoded to str) to the remote PTY.
                    try:
                        self.backend.send_input_to_shell(data.decode('utf-8', 'ignore'))
                    except Exception as exc:
                        LOGGER.warning("Failed sending input to remote shell: %s", exc)
                        break

            except Exception as e:
                LOGGER.exception("Shell bridge error: %s", e)
            finally:
                channel.close()
                self.shell_event.set()

        threading.Thread(target=shell_handler, daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        """Handle exec requests (non-interactive commands)."""
        command_str = command.decode()
        LOGGER.info("Exec request: %s", command_str)
        
        def exec_handler():
            try:
                output = self.backend.execute_in_shell(command_str)
                if output:
                    channel.sendall(output.encode())
                channel.send_exit_status(0)
            except JupyterBackendError as e:
                err = f"ERROR executing via Jupyter: {e}\n"
                channel.sendall_stderr(err.encode())
                channel.send_exit_status(1)
            except Exception as e:
                LOGGER.exception("Unexpected error processing exec")
                channel.sendall_stderr(f"Error: {e}\n".encode())
                channel.send_exit_status(1)
            finally:
                channel.close()
                self.exec_event.set()
        
        threading.Thread(target=exec_handler, daemon=True).start()
        return True

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        """Handle PTY requests for interactive sessions."""
        LOGGER.info("PTY request: term=%s size=%dx%d", term, width, height)
        try:
            # Set the initial PTY size.
            self.backend.resize_pty(rows=height, cols=width)
        except Exception as e:
            LOGGER.error("Failed to set initial PTY size: %s", e)
        return True

    def check_channel_window_change_request(
        self, channel, width, height, pixelwidth, pixelheight
    ):
        """Handle terminal window resizing."""
        LOGGER.info("Window resize request to %dx%d", width, height)
        try:
            self.backend.resize_pty(rows=height, cols=width)
        except Exception as e:
            LOGGER.error("Failed to resize PTY: %s", e)
        return True


class JuypterSSHServer:
    """Encapsulates socket listening and per-connection handling with polished UX."""

    def __init__(self, jupyter_url: str, host: str = "0.0.0.0", port: int = 2222, host_key_path: Optional[str] = None):
        self.jupyter_url = jupyter_url
        self.host = host
        self.port = port
        # Use persistent RSA keypair to avoid fingerprint mismatch.
        self.host_key = self._load_or_generate_host_key(host_key_path)

        # Warm-up backend for snappy first connection (shown with a spinner).
        self._warm_backend: Optional[JupyterBackend] = None

        threading.Thread(target=self._init_warm_backend, daemon=True).start()

    @staticmethod
    def _load_or_generate_host_key(path: Optional[str]) -> paramiko.PKey:
        if path and os.path.exists(path):
            return paramiko.RSAKey(filename=path)
        
        # Use a hardcoded RSA key to ensure consistent fingerprints
        # This prevents "host key changed" warnings on client reconnects
        # Note: This is for convenience, not cryptographic security
        import io
        
        # Pre-generated RSA private key in PEM format (2048-bit)
        # This ensures consistent fingerprints across server restarts
        rsa_private_key_pem = """-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAv0Wja1JIq447xwCcho1F5uZiA7mNVUtsrDEhLKSxyBizlzvu
aogc51rWBt+NyXyBIoWDSpkAs8woIfmXoIeQu2XI2ICBRccMubKUC66oqzU78JAi
Zv0KQtM4ttyTPCIsq2wN6klnLouY7hdE4NoWWklDyRnqm7tMf2JMW3p0sO1M3nLb
jUZykInxAxmMvcjRg4SWDkBdpAOHiPYAHkfJnSgaKLBFowdXKEmoWxHdgfkPxP/L
NBpo0n3dLjzK6ajcFRvILXbZhuIfIuHeQVCK8H73T4JgUigZQn4N9C30heBZxJAN
WI0lZa4dgGpotuJlV7fxjQaKn6f0AEMdXI0mUwIDAQABAoIBABB+fVquZFTi9ZWy
IE1cFmiUemRO1njCAdORgwZaB3i1ZJtIkEVAipmK1EUQdyYmZe5nrAw9SHm4w8c2
QlSWDC2U1+6PmlY9lYPX+ftN6v6knxAeJdFSxdVAaLYgLFQ1sDtyHHsVLGAvqpbx
i7+GHwJXKhDH+trGGpErlWEYHML69UVXhLFxwC35Jwydr8D6ZfiTFxMFtC2DnMY4
KAPAvZlJBqiMiu6rsZKGiypWmE3+9n+0oM57sZ9hshypOSVraAYPkMj8Mp88/Hbt
C99TrS1XUdyH/HdnSilTuEX2rMwkZtcKD4dxWHXY8byOAEc0QdXbPD2+5XDxtSL2
iTvr7kUCgYEA+PzzpL75paHJoZb8B3RqkMA3bWi8MuJ/2JM4MRUaQqjC9EP+Kaex
AXjuNae7biHNWTtRIhL+l6mXPw6k4M+jFvYmms9mRy48haUyhSC3u5VZi5JjRh91
scBmeUGXJQYq5ELv5VGEqpkF5AQ6Tnz4F/wlIxtHNAftgb1mScFEzycCgYEAxKiX
BDXDM/9WeJvCAKW+90TCbYRBUjkWUls77fpxzCsb7USPKbhQRsWpPPuZLL0WPf40
cmeXhTEtCIL2HqnFvogW9CGpOFe2n1DRLAoJVE3UK5TQPTfZZxhfZVSfEMf46Hl/
yb15rtxEOd7EgVwdCKiZWPcwMGQsOwNNVlClqvUCgYEA2Wi+MidTg44OqptUvAmq
F3TPsSgX1PKzoV+DXFBJ2tTTTkikgKjdRSTcE1u/rH21eenygSdGyRUbbMMTsv17
McyDjv/0FclIrYW+5EHaTOAvDVEogA1uTmRq1gwwtvJ4t1G/eWRBzFjLrPsIEorK
ct8Ham0iMkuN1pCT5Wjt9VcCgYEAsyoRI5HDfIzk/86Pqb1XRLlNFS+Hv1wpHPDn
oYEoyeSAdeKfN1gnMsMD034458yBBguhRpVgMsVBjN6bUgZEFLixiMtd+unWhEDB
wIiIRVj+spHKQeuu0kEfMBcvL7+v4kRHCsnnoUolkj+E8YG1Jd1MkAPr0DqDHWR9
weSJej0CgYEA3jPGs6jzPNVdoFmH16nelWsSsIVm2FkxV89NWV89IotW7J0iUB/q
8+ZweFpPDE6rDdHoTBK8UBE98AhsOJpiXwLPDuOVXY8CBbkpaA3ezwwYTswc2qtw
rVTM/+Yl7cvk/9/0BZEvXiNajLgYACK4LhaA2Nf83kQIMttTyWfPZiI=
-----END RSA PRIVATE KEY-----"""
        
        # Load the key from the PEM string
        key_file = io.StringIO(rsa_private_key_pem)
        key = paramiko.RSAKey.from_private_key(key_file)
        
        if path:
            key.write_private_key_file(path)
        return key

    def _handle_client(self, client_socket):
        """Handle individual client connections."""
        transport = None
        try:
            backend = JupyterBackend(self.jupyter_url)
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Register SFTP subsystem with our custom backend-driven interface
            transport.set_subsystem_handler("sftp", paramiko.SFTPServer, JupyterSFTPServer, backend=backend)

            server = SSHHandler(backend)
            transport.start_server(server=server)
            
            # Wait for authentication and channels
            channel = transport.accept(20)  # 20 second timeout
            if channel is None:
                LOGGER.warning("No channel established within timeout")
                return
                
            # Keep connection alive until client disconnects
            while transport.is_active():
                time.sleep(0.1)
                
        except Exception as e:
            LOGGER.warning("Client connection error: %s", e)
        finally:
            if transport:
                try:
                    transport.close()
                except:
                    pass

    def serve_forever(self):
        """Main server loop."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            sock.bind((self.host, self.port))
            sock.listen(100)
            LOGGER.info("SSH server listening on %s:%s", self.host, self.port)
            
            while True:
                try:
                    client, addr = sock.accept()
                    try:
                        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    except Exception:
                        pass  # Not fatal; continue
                    LOGGER.info("Incoming connection from %s:%s", *addr)
                    t = threading.Thread(target=self._handle_client, args=(client,), daemon=True)
                    t.start()
                except KeyboardInterrupt:
                    LOGGER.info("Server interrupted by user")
                    break
                except Exception as e:
                    LOGGER.error("Error accepting connection: %s", e)
                    
        finally:
            sock.close()
            LOGGER.info("SSH server stopped")

    # ------------------------------------------------------------
    def _init_warm_backend(self):
        """Create a background JupyterBackend instance immediately so that the
        Jupyter server spawns a kernel ahead of the first SSH connection."""
        try:
            from rich.console import Console
            from rich.progress import Progress, SpinnerColumn, TextColumn

            console = Console()
            with Progress(
                SpinnerColumn(style="bold green"),
                TextColumn("[progress.description]{task.description}"),
                transient=True,
                console=console,
            ) as progress:
                progress.add_task(description="Spawning Jupyter kernel…", total=None)
                backend = JupyterBackend(self.jupyter_url)
                backend.execute_code("pass", timeout=20)
                self._warm_backend = backend
                LOGGER.info("Warm-up kernel ready (id=%s)", backend.kernel_id)
        except Exception as exc:
            # Fallback without fancy UI
            try:
                backend = JupyterBackend(self.jupyter_url)
                backend.execute_code("pass", timeout=20)
                self._warm_backend = backend
                LOGGER.info("Warm-up kernel ready (id=%s)", backend.kernel_id)
            except Exception as exc2:
                LOGGER.warning("Warm-up kernel init failed: %s", exc2) 