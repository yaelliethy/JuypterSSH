import json
import typing
import uuid
import logging
import time
from typing import Optional, Dict, Any, List
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import requests
import websockets  # type: ignore
import asyncio
import base64
import os
import aiohttp
import select
import textwrap
import subprocess
import fcntl
import termios
import threading
import sys


log_level = logging.INFO if os.getenv("JUYPTERSSH_DEBUG") == "1" else logging.ERROR
logging.basicConfig(level=log_level, format="%(levelname)s %(name)s - %(message)s")

LOGGER = logging.getLogger(__name__)


class JupyterBackendError(Exception):
    """Generic error talking to the Jupyter backend."""


class JupyterBackend:
    """Simple helper around Jupyter REST + WebSocket APIs.

    This class focuses on just what we need for the fake SSH/SFTP server:
    1. Create (or reuse) a kernel session.
    2. Execute Python code in that kernel and fetch stdout / stderr output.
    3. Access the Contents API for basic file operations (list/read/write).
    """

    def __init__(self, jupyter_url: str):
        self.original_url = jupyter_url.rstrip("/")
        self.base_url, self.token = self._parse_jupyter_url(self.original_url)
        self.session: Optional[Dict[str, Any]] = None  # JSON response from /api/sessions
        self.kernel_id: Optional[str] = None
        self.xsrf_token: Optional[str] = None

        self.session_id = str(uuid.uuid4())  # Our own identifier when talking on websockets

        # Persistent websocket state
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._reader_task: Optional[asyncio.Task] = None
        self._queue: "asyncio.Queue[dict]" = asyncio.Queue()

        # Dedicated event loop running in background thread
        self._loop = asyncio.new_event_loop()
        import threading
        threading.Thread(target=self._loop.run_forever, daemon=True).start()

        # List of callables getting raw text from kernel 'stream' messages.
        self._stream_subscribers: list[typing.Callable[[str], None]] = []

        LOGGER.info("Parsed Jupyter URL. Base=%s Token=%s", self.base_url, self.token)

    # ---------------------------------------------------------------------
    # URL helpers
    # ---------------------------------------------------------------------
    @staticmethod
    def _parse_jupyter_url(url: str):
        """Return (base_url_without_trailing_slash, token) from the provided Jupyter URL.

        The URL can be one of:
        1. https://host/user/foo/lab?token=ABC
        2. https://host/k/<id>/<token>/proxy
        3. https://kkb-production.jupyter-proxy.kaggle.net/k/<id>/<token>/proxy

        We try query param first, then path segment heuristics.
        """
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if "token" in query and query["token"]:
            token = query["token"][0]
            # Strip query component
            clean_parts = parsed._replace(query="")
            base_url = urlunparse(clean_parts).rstrip("/")
            return base_url, token

        # Fallback: assume token is the next-to-last segment in the path
        segments = parsed.path.rstrip("/").split("/")
        if len(segments) >= 2:
            token = segments[-2]
            # For Kaggle URLs like /k/<id>/<token>/proxy, preserve the proxy path
            # The API endpoints should be accessed as /k/<id>/<token>/proxy/api/...
            if len(segments) >= 4 and segments[1] == "k" and segments[-1] == "proxy":
                # Keep the full proxy path: /k/<id>/<token>/proxy
                new_path = "/".join(segments[:-1])  # Remove only the final /proxy for now
                clean_parts = parsed._replace(path=new_path, query="")
                base_url = urlunparse(clean_parts).rstrip("/")
                # But actually, let's preserve the /proxy part too
                base_url = f"{base_url}/proxy"
            elif len(segments) >= 4 and segments[1] == "k":
                # Keep: /k/<id>
                new_path = "/".join(segments[:3])
                clean_parts = parsed._replace(path=new_path, query="")
                base_url = urlunparse(clean_parts).rstrip("/")
            else:
                # Remove token + following segment (often "proxy" or "lab")
                new_path = "/".join(segments[:-2])
                clean_parts = parsed._replace(path=new_path, query="")
                base_url = urlunparse(clean_parts).rstrip("/")
            return base_url, token

        raise ValueError("Could not parse Jupyter URL for token: %s" % url)

    def _build_url(self, *parts, **query) -> str:
        url = f"{self.base_url}/" + "/".join(str(p).strip("/") for p in parts if p is not None)
        if query or self.token:
            q = {**query}
            # Append token automatically unless caller explicitly supplies token
            if "token" not in q and self.token:
                q["token"] = self.token
            url = f"{url}?{urlencode(q)}"
        LOGGER.debug("Built URL: %s", url)
        return url

    # ---------------------------------------------------------------------
    def _kernel_channels_url(self):
        """Return full websocket URL for kernel channels with session_id."""
        # Manually construct the websocket URL. For proxy-based auth (like Kaggle),
        # the token is part of the base URL path, and should not be in the query string.
        # The session_id, however, is required.
        # self.kernel_id can be None, so filter it out before joining
        path_segments = ["api", "kernels", self.kernel_id, "channels"]
        path_part = "/".join(segment for segment in path_segments if segment is not None)
        query_part = urlencode({"session_id": self.session_id})
        full_http_url = f"{self.base_url}/{path_part}?{query_part}"
        
        ws_parsed = urlparse(full_http_url)
        scheme = "wss" if ws_parsed.scheme == "https" else "ws"
        return urlunparse(ws_parsed._replace(scheme=scheme))

    # ---------------------------------------------------------------------
    # Kernel & execution
    # ---------------------------------------------------------------------
    def _ensure_session_and_kernel(self):
        if self.kernel_id:
            return
        
        # Fetch XSRF token from the main page
        try:
            resp = requests.get(self.base_url, timeout=15)
            if '_xsrf' in resp.cookies:
                self.xsrf_token = resp.cookies['_xsrf']
                LOGGER.info("Fetched XSRF token: %s", self.xsrf_token)
            else:
                LOGGER.warning("Could not fetch XSRF token from base URL")
        except Exception as e:
            LOGGER.error("Failed to fetch XSRF token: %s", e)

        # Create a new session → kernel
        payload = {
            "path": f"ssh-session-{self.session_id}.ipynb",
            "type": "notebook",
            "name": "",
            "notebook": {
                "path": f"ssh-session-{self.session_id}.ipynb",
                "name": ""
            },
            "kernel": {"name": "python3"},
        }
        url = self._build_url("api", "sessions")
        LOGGER.info("Creating new Jupyter session: POST %s", url)
        resp = requests.post(url, json=payload, timeout=15)
        if resp.status_code != 201:
            raise JupyterBackendError(f"Failed to create Jupyter session: {resp.status_code} {resp.text}")
        self.session = resp.json()
        self.kernel_id = self.session["kernel"]["id"]  # type: ignore[index]
        LOGGER.info("Created session %s with kernel %s", self.session["id"], self.kernel_id)  # type: ignore[index]

    async def _websocket_messages(self):
        """Internal async generator yielding websocket messages for the current kernel."""
        # This function is not currently used, but we'll keep it for potential future use.
        pass

    async def execute_code_async(self, code: str, timeout: int = 30) -> str:
        """Execute Python code in the remote Jupyter kernel (async implementation).

        Returns combined stdout/stderr output as a string.
        """
        LOGGER.info("execute_code_async called with code: %r", code[:100])
        self._ensure_session_and_kernel()
        await self._ensure_ws()

        msg_id = uuid.uuid4().hex
        header = {
            "msg_id": msg_id,
            "username": "ssh",
            "session": self.session_id,
            "msg_type": "execute_request",
            "version": "5.3",
        }
        execute_msg = {
            "header": header,
            "parent_header": {},
            "metadata": {},
            "content": {
                "code": code,
                "silent": False,
                "store_history": False,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True,
            },
            "channel": "shell",
        }

        # Send execute request
        await self._ws.send_str(json.dumps(execute_msg))  # type: ignore

        output_parts: List[str] = []

        # Wait for matching messages
        while True:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                raise JupyterBackendError("Timeout waiting for kernel response")

            p_header = msg.get("parent_header", {})
            if p_header.get("msg_id") != msg_id:
                # Message for another request → skip
                continue

            mtype = msg.get("msg_type")
            if mtype == "stream":
                output_parts.append(msg.get("content", {}).get("text", ""))
            elif mtype in {"execute_result", "display_data"}:
                data = msg.get("content", {}).get("data", {})
                if "text/plain" in data:
                    output_parts.append(str(data["text/plain"]) + "\n")
            elif mtype == "error":
                tb = "\n".join(msg.get("content", {}).get("traceback", []))
                output_parts.append(tb + "\n")
            elif mtype == "status" and msg.get("content", {}).get("execution_state") == "idle":
                break

        return "".join(output_parts)

    def execute_code(self, code: str, timeout: int = 30) -> str:
        """Schedule execute_code_async in backend's dedicated loop and block until result."""
        LOGGER.info("execute_code (sync) called with: %r", code[:50])
        fut = asyncio.run_coroutine_threadsafe(self.execute_code_async(code, timeout), self._loop)
        return fut.result()

    def stream_code(self, code: str, output_callback, timeout: int = 30):
        """Sync wrapper for stream_code_async."""
        future = asyncio.run_coroutine_threadsafe(
            self.stream_code_async(code, output_callback, timeout), self._loop
        )
        future.result()

    async def stream_code_async(self, code: str, output_callback, timeout: int = 30):
        """Execute code and stream output back via a callback."""
        LOGGER.info("stream_code_async called with code: %r", code[:100])
        self._ensure_session_and_kernel()
        await self._ensure_ws()

        msg_id = uuid.uuid4().hex
        execute_msg = {
            "header": {
                "msg_id": msg_id,
                "username": "ssh",
                "session": self.session_id,
                "msg_type": "execute_request",
                "version": "5.3",
            },
            "parent_header": {},
            "metadata": {},
            "content": {
                "code": code,
                "silent": False,
                "store_history": False,
                "user_expressions": {},
                "allow_stdin": False,
                "stop_on_error": True,
            },
            "channel": "shell",
        }

        if self._ws:
            await self._ws.send_str(json.dumps(execute_msg))
        else:
            # This should ideally not happen due to _ensure_ws()
            LOGGER.error("Websocket not available, cannot execute code.")
            output_callback("\\n[Websocket connection not available]\\n")
            return

        while True:
            try:
                msg = await asyncio.wait_for(self._queue.get(), timeout=timeout)
            except asyncio.TimeoutError:
                output_callback("\\n[Timeout waiting for kernel response]")
                break

            p_header = msg.get("parent_header", {})
            if p_header.get("msg_id") != msg_id:
                continue

            mtype = msg.get("msg_type")
            content = msg.get("content", {})
            
            if mtype == "stream":
                output_callback(content.get("text", ""))
            elif mtype in {"execute_result", "display_data"}:
                data = content.get("data", {})
                if "text/plain" in data:
                    output_callback(str(data["text/plain"]))
            elif mtype == "error":
                tb = "\\n".join(content.get("traceback", []))
                output_callback(f"\\n--- KERNEL ERROR ---\\n{tb}\\n--- END KERNEL ERROR ---\\n")
            elif mtype == "status" and content.get("execution_state") == "idle":
                break

    def execute_in_shell(self, command: str, timeout: int = 30) -> str:
        """This is now a legacy method. Use stream_in_shell for interactive sessions."""
        all_output = []
        def cb(chunk):
            all_output.append(chunk)
        self.stream_in_shell(command, cb, timeout)
        return "".join(all_output)

    def stream_in_shell(self, command: str, output_callback, timeout: int = 30):
        """Runs a command in the persistent PTY-based shell and streams output."""
        script = f"""
        import os, pty, select, base64, time, subprocess, textwrap

        command_to_run = base64.b64encode("{command}".encode('utf-8')).decode('ascii')

        # --- Globals on the Kernel ---
        # 'bash_master_fd': The file descriptor for the master side of the PTY.
        # 'bash_proc': The subprocess.Popen object for the bash process.

        if 'bash_master_fd' not in globals() or globals()['bash_proc'].poll() is not None:
            if 'bash_master_fd' in globals():
                try:
                    os.close(globals()['bash_master_fd'])
                except:
                    pass
                del globals()['bash_master_fd']
                del globals()['bash_proc']

            master_fd, slave_fd = pty.openpty()
            
            # Configure the slave side for proper signal handling before starting bash
            try:
                attrs = termios.tcgetattr(slave_fd)
                # Enable signal generation and canonical processing
                attrs[3] |= termios.ISIG | termios.ICANON | termios.ECHO
                # Set control characters properly
                attrs[6][termios.VINTR] = 3   # Ctrl+C
                attrs[6][termios.VQUIT] = 28  # Ctrl+\\
                attrs[6][termios.VSUSP] = 26  # Ctrl+Z
                attrs[6][termios.VEOF] = 4    # Ctrl+D
                termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
            except Exception:
                pass  # Continue even if termios setup fails

            # Start an interactive bash shell with proper process group (line-buffered)
            proc = subprocess.Popen(
                ['stdbuf', '-oL', '-eL', '/bin/bash', '-i'],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                bufsize=0,
                close_fds=True,
                preexec_fn=os.setsid,  # Create new session/process group
                env=dict(os.environ, TERM='xterm-256color')  # Set proper terminal type
            )
            
            # Close slave fd in parent - child has its own copy
            os.close(slave_fd)
            
            # Store references globally so that subsequent calls can reuse them
            globals()['bash_master_fd'] = master_fd
            globals()['bash_proc'] = proc
            
            # Make the PTY master non-blocking for the reader loop
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Read initial shell setup output and discard it
            time.sleep(0.2)
            try:
                while select.select([master_fd], [], [], 0.1)[0]:
                    os.read(master_fd, 1024)
            except:
                pass

        master_fd = globals()['bash_master_fd']
        proc = globals()['bash_proc']
        
        # Decode and send the user's command
        command_decoded = base64.b64decode(command_to_run).decode('utf-8')
        os.write(master_fd, (command_decoded + '\\n').encode('utf-8'))
        
        # For interactive commands, we need to stream output more persistently
        # Instead of breaking on timeout, we'll continue reading for a reasonable duration
        start_time = time.time()
        last_output_time = time.time()
        output_received = False
        
        while time.time() - start_time < 30:  # Maximum 30 seconds total
            ready, _, _ = select.select([master_fd], [], [], 0.1)
            
            if ready:
                try:
                    data = os.read(master_fd, 1024)
                    if data:
                        output_received = True
                        last_output_time = time.time()
                        decoded = data.decode('utf-8', 'replace')
                        print(decoded, end='', flush=True)
                    else:  # EOF
                        print("\\n[Shell process ended]\\n", flush=True)
                        break
                except OSError as e:
                    print(f"\\n[PTY read error: {{e}}]\\n", flush=True)
                    break
            else:
                # No immediate output available
                # For interactive commands, don't break immediately on timeout
                # Instead, check if we've been waiting too long without any output
                if output_received and time.time() - last_output_time > 2.0:
                    # If we've seen output but nothing for 2 seconds, command likely finished
                    break
                elif not output_received and time.time() - start_time > 5.0:
                    # If no output at all for 5 seconds, something's wrong
                    print("\\n[No output received - command may have failed]\\n", flush=True)
                    break
                    
            # Check if process has died
            if proc.poll() is not None:
                print("\\n[Shell process has exited]\\n", flush=True)
                break
        
        # Read any remaining output
        try:
            while select.select([master_fd], [], [], 0.05)[0]:
                data = os.read(master_fd, 1024)
                if data:
                    print(data.decode('utf-8', 'replace'), end='', flush=True)
                else:
                    break
        except:
            pass
        """
        self.stream_code(textwrap.dedent(script), output_callback, timeout=timeout)

    # ---------------------------------------------------------------------
    # Contents API helpers (minimal subset)
    # ---------------------------------------------------------------------
    def list_dir(self, path: str = "") -> List[Dict[str, Any]]:
        url = self._build_url("api", "contents", path)
        LOGGER.info("Attempting to list directory: %s", url)
        resp = requests.get(url, params={"content": "1"}, timeout=15)
        LOGGER.info("Response status: %d, headers: %s", resp.status_code, dict(resp.headers))
        if resp.status_code != 200:
            LOGGER.error("Full response text: %s", resp.text)
            raise JupyterBackendError(f"Failed to list dir {path}: {resp.status_code} {resp.text}")
        model = resp.json()
        if model["type"] != "directory":
            raise JupyterBackendError(f"{path} is not a directory on Jupyter backend")
        return model.get("content", [])

    def get_file(self, path: str) -> bytes:
        url = self._build_url("api", "contents", path)
        resp = requests.get(url, params={"format": "text"}, timeout=15)
        if resp.status_code != 200:
            raise JupyterBackendError(f"Failed to fetch file {path}: {resp.status_code} {resp.text}")
        model = resp.json()
        if model["type"] != "file":
            raise JupyterBackendError(f"{path} is not a file")
        return model.get("content", "").encode()

    def save_file(self, path: str, data: bytes, format_: str = "text") -> None:
        url = self._build_url("api", "contents", path)
        payload = {
            "type": "file",
            "format": format_,
            "content": data.decode() if isinstance(data, (bytes, bytearray)) else data,
        }
        resp = requests.put(url, json=payload, timeout=15)
        if resp.status_code not in {200, 201}:
            raise JupyterBackendError(f"Failed to save file {path}: {resp.status_code} {resp.text}")

    # ---------------------------------------------------------------------
    # Added helpers used by SFTP layer
    # ---------------------------------------------------------------------
    def delete_path(self, path: str) -> None:
        """Delete a file or directory (recursively) via Jupyter Contents API."""
        url = self._build_url("api", "contents", path)
        resp = requests.delete(url, timeout=15)
        if resp.status_code not in {200, 204}:
            raise JupyterBackendError(f"Failed to delete {path}: {resp.status_code} {resp.text}")

    def rename_path(self, old_path: str, new_path: str) -> None:
        url = self._build_url("api", "contents", old_path)
        payload = {"path": new_path}
        resp = requests.patch(url, json=payload, timeout=15)
        if resp.status_code != 200:
            raise JupyterBackendError(
                f"Failed to rename {old_path} -> {new_path}: {resp.status_code} {resp.text}"
            )

    def create_dir(self, path: str) -> None:
        url = self._build_url("api", "contents", path)
        payload = {"type": "directory"}
        resp = requests.put(url, json=payload, timeout=15)
        if resp.status_code not in {200, 201}:
            raise JupyterBackendError(f"Failed to create dir {path}: {resp.status_code} {resp.text}")

    # ---------------------------------------------------------------------

    def __repr__(self):
        return f"<JupyterBackend base={self.base_url} kernel={self.kernel_id}>"

    # ------------------------------------------------------------------
    # Websocket helpers
    # ------------------------------------------------------------------
    def _ws_headers(self) -> dict:
        """Return headers required for the websocket upgrade that mimic browser."""
        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:135.0) Gecko/20100101 Firefox/135.0',
            'Origin': self.base_url,
            'Connection': 'keep-alive, Upgrade',
            'Upgrade': 'websocket',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
        }
        if self.xsrf_token:
            headers['Cookie'] = f'_xsrf={self.xsrf_token}'
        if self.token:
            headers['Authorization'] = f"token {self.token}"
        return headers

    async def _ensure_ws(self):
        """Ensure a persistent websocket connection is established and reader loop running."""
        if self._ws and not self._ws.closed:
            return

        ws_url = self._kernel_channels_url()
        LOGGER.info("Opening persistent websocket %s", ws_url)
        session = aiohttp.ClientSession()
        self._ws = await session.ws_connect(
            ws_url,
            headers=self._ws_headers(),
            protocols=('v1.kernel.websocket.jupyter.org',),
            compress=0,
        )

        # Start background reader
        self._reader_task = asyncio.create_task(self._reader_loop(), name="jupyter-ws-reader")

    async def _reader_loop(self):
        """Background task that reads all websocket messages and puts them on queue."""
        assert self._ws is not None
        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    obj = json.loads(msg.data)
                    # Fan-out: notify any live subscribers of stdout/stderr text *before*
                    # we enqueue, so consumers get immediate feedback.
                    if obj.get("msg_type") == "stream":
                        txt = obj.get("content", {}).get("text", "")
                        if txt:
                            for cb in list(self._stream_subscribers):
                                try:
                                    cb(txt)
                                except Exception as exc:
                                    LOGGER.debug("Stream subscriber raised: %s", exc)
                    await self._queue.put(obj)
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR):
                    break
        except Exception as exc:
            LOGGER.error("Websocket reader loop error: %s", exc)
        finally:
            await self._ws.close()

    async def execute_in_shell_async(self, command: str, timeout: int = 30) -> str:
        """Constructs and runs a Python script on the kernel to manage a persistent, non-PTY shell."""
        
        script = f"""
        import os, subprocess, fcntl, json, time, uuid, base64, select

        # The command to run, base64 encoded to avoid escaping issues.
        command_to_run = base64.b64decode("{base64.b64encode(command.encode('utf-8')).decode('ascii')}").decode('utf-8')

        # --- Globals on the Kernel ---
        # 'bash_proc': The subprocess.Popen object for the bash process.

        # 1. Setup shell if not already running
        if 'bash_proc' not in globals() or globals()['bash_proc'].poll() is not None:
            # -i for interactive mode to keep it alive.
            # We use pipes instead of a PTY.
            proc = subprocess.Popen(
                ['stdbuf', '-oL', '-eL', '/bin/bash', '-i'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True, # Use text mode for automatic encoding/decoding
                bufsize=1  # Line-buffered
            )
            globals()['bash_proc'] = proc
            
            # Set stdout/stderr to non-blocking
            flags = fcntl.fcntl(proc.stdout, fcntl.F_GETFL)
            fcntl.fcntl(proc.stdout, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            flags = fcntl.fcntl(proc.stderr, fcntl.F_GETFL)
            fcntl.fcntl(proc.stderr, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Command echo is not suppressed, it will be cleaned from output.
            time.sleep(0.1)
            # Discard initial output (like prompts)
            try:
                proc.stdout.read()
                proc.stderr.read()
            except (IOError, TypeError): # Can be EAGAIN or None
                pass


        # --- Command Execution ---
        bash_proc = globals()['bash_proc']
        marker = f"END_OF_COMMAND_{{uuid.uuid4().hex}}"
        read_timeout = 10.0 # seconds

        # 2. Write the user's command, followed by the marker command.
        bash_proc.stdin.write(command_to_run + '\\n')
        bash_proc.stdin.flush()
        # Use echo -n to avoid a newline after the marker, so the prompt follows immediately.
        bash_proc.stdin.write('echo -n "' + marker + '"\\n')
        bash_proc.stdin.flush()

        # 3. Read from stdout/stderr until we see the marker, and then a little more.
        output_buffer = ""
        start_time = time.time()

        while (time.time() - start_time) < read_timeout:
            ready_to_read, _, _ = select.select([bash_proc.stdout, bash_proc.stderr], [], [], 0.1)
            
            for stream in ready_to_read:
                try:
                    line = stream.readline()
                    if line:
                        output_buffer += line
                except (IOError, TypeError):
                    pass # Ignore errors on a single read
            
            # Once we have the marker, we wait a bit for the prompt to arrive.
            if marker in output_buffer:
                time.sleep(0.05) # Wait for prompt
                # Try one last read
                ready_to_read, _, _ = select.select([bash_proc.stdout, bash_proc.stderr], [], [], 0.1)
                for stream in ready_to_read:
                    try:
                        line = stream.readline()
                        if line:
                            output_buffer += line
                    except (IOError, TypeError):
                        pass
                break # Exit the read loop


        # 4. Clean up the output.
        marker_pos = output_buffer.rfind(marker)
        if marker_pos != -1:
            output_str = output_buffer[:marker_pos]
            prompt = output_buffer[marker_pos:].replace(marker, "")

            # Since we can't suppress command echo, we manually remove the echoed command.
            # The first line of the output should be the command itself.
            lines = output_str.splitlines()
            if lines and command_to_run.strip() == lines[0].strip():
                # This is the echoed command. Remove it.
                output_str = '\\n'.join(lines[1:])
                
            final_output = output_str + prompt
        else:
            final_output = output_buffer.strip() + "\\n[COMMAND TIMEOUT]"

        print(final_output, end='')
        """
        
        return await self.execute_code_async(textwrap.dedent(script), timeout=timeout)

    def send_input_to_shell(self, input_text: str):
        """Send input to the currently running shell session."""
        script = f"""
        import os, base64, textwrap

        input_to_send = base64.b64decode("{base64.b64encode(input_text.encode('utf-8')).decode('ascii')}").decode('utf-8')

        if 'bash_master_fd' in globals():
            master_fd = globals()['bash_master_fd']
            try:
                os.write(master_fd, input_to_send.encode('utf-8'))
            except Exception as e:
                # Still surface the error, but do not pollute the normal shell output.
                print(f"[Error sending input: {{e}}]", flush=True)
        else:
            print("[No active shell session to send input to]", flush=True)
        """
        
        # Use execute_code for this since we don't need streaming output for input sending
        result = self.execute_code(textwrap.dedent(script))
        return result 

    def resize_pty(self, rows: int, cols: int):
        """Sends an ioctl to the remote PTY to set its window size."""
        script = f"""
        import os, fcntl, termios, struct
        if 'bash_master_fd' in globals():
            master_fd = globals()['bash_master_fd']
            try:
                winsize = struct.pack('HHHH', {rows}, {cols}, 0, 0)
                fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
            except Exception as e:
                # Log error on kernel side for debugging, but don't fail loudly.
                print(f"[Error resizing PTY: {{e}}]", flush=True)
        """
        try:
            # Fire-and-forget with short timeout.
            self.execute_code(textwrap.dedent(script), timeout=5)
        except Exception as e:
            LOGGER.warning("Resize PTY command failed to execute: %s", e)

    def start_interactive_shell(self, output_callback):
        """Ensure a persistent PTY shell is running on the remote kernel and continuously
        forward its stdout/stderr to the given callback.

        The implementation works in two steps:
        1. Run (once) a small Python snippet on the remote kernel that:
           • Spawns – if not already running – an interactive `/bin/bash` in a PTY.
           • Starts a background *reader* thread that non-blockingly reads from the
             PTY master side and prints everything it sees to the notebook stdout.
           These prints are then delivered to us as normal `stream` messages via
           the websocket connection.
        2. Locally, spin up a coroutine on the backend's private event-loop that
           consumes those websocket `stream` messages and sends the contained text
           to the supplied ``output_callback``.
        """

        # ------------------------------------------------------------------
        # 1) Remote initialisation snippet (runs extremely quickly).
        # ------------------------------------------------------------------
        init_script = r"""
import os, pty, subprocess, threading, select, sys, time, fcntl, tty

# We only want to run the expensive setup once per kernel.
if '_interactive_shell_ready' not in globals():
    master_fd, slave_fd = pty.openpty()
    
    # Configure the slave side for proper signal handling before starting bash
    try:
        attrs = termios.tcgetattr(slave_fd)
        # Enable signal generation and canonical processing
        attrs[3] |= termios.ISIG | termios.ICANON | termios.ECHO
        # Set control characters properly
        attrs[6][termios.VINTR] = 3   # Ctrl+C
        attrs[6][termios.VQUIT] = 28  # Ctrl+\\
        attrs[6][termios.VSUSP] = 26  # Ctrl+Z
        attrs[6][termios.VEOF] = 4    # Ctrl+D
        termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
    except Exception:
        pass  # Continue even if termios setup fails

    # Start an interactive bash shell with proper process group (line-buffered)
    proc = subprocess.Popen(
        ['/usr/bin/stdbuf', '-oL', '-eL', '/bin/bash', '-i'],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        bufsize=0,
        close_fds=True,
        preexec_fn=os.setsid,  # Create new session/process group
        env=dict(os.environ, TERM='xterm-256color')  # Set proper terminal type
    )

    # Close slave fd in parent - child has its own copy
    os.close(slave_fd)

    # Store references globally so that subsequent calls can reuse them
    globals()['bash_master_fd'] = master_fd
    globals()['bash_proc'] = proc

    # Make the PTY master non-blocking for the reader loop
    flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    # ------------------------------------------------------------
    # Fast reader implemented in C for lower per-byte overhead.
    # We build the shared library once per kernel (gcc is available
    # in most Kaggle images). Fallback to the pure-Python reader if
    # compilation fails.
    # ------------------------------------------------------------
    so_path = '/tmp/libpty_reader.so'
    use_c_reader = False
    try:
        if not os.path.exists(so_path):
            c_code = r'''
            #include <stdio.h>
            #include <unistd.h>
            #include <sys/select.h>
            #include <signal.h>
            
            static volatile int should_stop = 0;
            void sig_handler(int sig) { should_stop = 1; }
            
            void loop_read(int fd){
                signal(SIGTERM, sig_handler);
                signal(SIGINT, sig_handler);
                char buf[65536];
                for(;;){
                    if(should_stop) return;
                    fd_set rfds; FD_ZERO(&rfds); FD_SET(fd,&rfds);
                    struct timeval tv; tv.tv_sec=0; tv.tv_usec=20000; //20ms
                    int ret = select(fd+1, &rfds, NULL, NULL, &tv);
                    if(ret>0 && FD_ISSET(fd,&rfds)){
                        ssize_t n = read(fd, buf, sizeof(buf));
                        if(n<=0) return; // EOF or error
                        fwrite(buf, 1, n, stdout);
                    } else if(ret<0){ return; }
                }
            }
            '''
            import textwrap, subprocess, tempfile
            c_file = '/tmp/pty_reader.c'
            open(c_file,'w').write(textwrap.dedent(c_code))
            subprocess.check_call(['gcc','-shared','-fPIC','-O2', c_file, '-o', so_path])
        import ctypes
        lib = ctypes.CDLL(so_path)
        lib.loop_read.argtypes = [ctypes.c_int]

        def _reader_loop_c():
            lib.loop_read(master_fd)

        threading.Thread(target=_reader_loop_c, daemon=True).start()
        use_c_reader = True
    except Exception as _e:
        # Fall back to pure Python reader on any failure
        def _reader_loop_py():
            while True:
                try:
                    ready, _, _ = select.select([master_fd], [], [], 0.1)
                    if master_fd in ready:
                        chunk = os.read(master_fd, 8192)
                        if not chunk:
                            break
                        try:
                            sys.stdout.write(chunk.decode('utf-8','replace'))
                        except Exception:
                            sys.stdout.write(chunk.decode('latin1','replace'))
                        sys.stdout.flush()
                    if proc.poll() is not None:
                        break
                except Exception:
                    break
        threading.Thread(target=_reader_loop_py, daemon=True).start()

    # -------------------- NEW SENTINEL WATCHER --------------------
    def _shell_watcher():
        proc.wait()
        try:
            sys.stdout.write('\n[[BASH_EXITED]]\n')
            sys.stdout.flush()
        except Exception:
            pass
    threading.Thread(target=_shell_watcher, daemon=True).start()

    globals()['_interactive_shell_reader_c'] = use_c_reader
    globals()['_interactive_shell_ready'] = True
print('[interactive shell ready]', flush=True)
"""

        # Run the initialisation code – it is idempotent, so cost is low if already set up.
        try:
            self.execute_code(textwrap.dedent(init_script), timeout=15)
        except Exception as exc:
            LOGGER.error("Failed to initialise interactive shell: %s", exc)
            raise

        # ------------------------------------------------------------------
        # 2) Subscribe to kernel stream output – duplicates are ignored.
        # ------------------------------------------------------------------
        self.add_stream_subscriber(output_callback)

    # ------------------------------------------------------------------
    # Stream subscription helpers
    # ------------------------------------------------------------------
    def add_stream_subscriber(self, callback):
        """Register a callback to receive raw stdout/stderr text from the kernel."""
        if callback not in self._stream_subscribers:
            self._stream_subscribers.append(callback)

    def remove_stream_subscriber(self, callback):
        """Unregister a previously added stream subscriber."""
        if callback in self._stream_subscribers:
            self._stream_subscribers.remove(callback) 