import errno
import io
import os
import stat
import time
import threading
from typing import Any, Dict

import paramiko

from jupyter_backend import JupyterBackend, JupyterBackendError


class JupyterSFTPHandle(paramiko.SFTPHandle):
    """Simple file-handle backed by BytesIO in-memory buffer that syncs on close."""

    def __init__(self, flags: int, backend: JupyterBackend, path: str):
        super().__init__(flags)
        self.backend = backend
        self.path = path
        self.flags = flags
        self._lock = threading.Lock()

        # Local buffer for read/write
        self.io = io.BytesIO()

        try:
            original = self.backend.get_file(self.path)
            self.io.write(original)
        except JupyterBackendError:
            # File may not exist; that's okay if O_CREAT was supplied.
            if not (flags & os.O_CREAT):
                raise
        self._apply_open_flags()

    # ------------------------- helpers -------------------------
    def _apply_open_flags(self):
        """Interpret O_TRUNC / O_APPEND on the in-memory buffer."""
        if self.flags & os.O_TRUNC:
                self.io.seek(0)
                self.io.truncate(0)
        if self.flags & os.O_APPEND:
            self.io.seek(0, os.SEEK_END)

    def close(self):
        if self.flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND):
            with self._lock:
                self.io.seek(0)
                data = self.io.read()
                try:
                    self.backend.save_file(self.path, data)
                except JupyterBackendError:
                    return errno.EIO
        super().close()
        return paramiko.SFTP_OK  # type: ignore[attr-defined]

    def read(self, offset, length):  # type: ignore[override]
        with self._lock:
            self.io.seek(offset)
        return self.io.read(length)

    def write(self, offset, data):  # type: ignore[override]
        with self._lock:
            self.io.seek(offset)
            self.io.write(data)
        return paramiko.SFTP_OK  # type: ignore[attr-defined]

    # -----------------------------------------------------------
    def seek(self, offset, whence=io.SEEK_SET):  # type: ignore[override]
        return self.io.seek(offset, whence)

    def tell(self):  # type: ignore[override]
        return self.io.tell()

    def truncate(self, size):  # type: ignore[override]
        with self._lock:
            self.io.truncate(size)
        return paramiko.SFTP_OK  # type: ignore[attr-defined]


class JupyterSFTPServer(paramiko.SFTPServerInterface):
    """Paramiko SFTP interface implemented via Jupyter Contents API."""

    def __init__(self, server, *largs, backend: JupyterBackend, **kwargs):
        super().__init__(server, *largs, **kwargs)
        self.backend = backend

    # -----------------------------------------------------------
    def _jupyter_stat_to_attr(self, model: Dict[str, Any]) -> paramiko.SFTPAttributes:
        attr = paramiko.SFTPAttributes()
        attr.filename = model.get("name") or ""  # type: ignore[assignment]
        attr.st_mode = stat.S_IFDIR | 0o755 if model["type"] == "directory" else stat.S_IFREG | 0o644
        attr.st_size = model.get("size", 0)
        attr.st_mtime = int(time.time())
        attr.st_uid = 1000
        attr.st_gid = 1000
        return attr

    # -----------------------------------------------------------
    # Helper utilities
    # -----------------------------------------------------------
    def _clean_path(self, path: str) -> str:
        """Normalise path and block parent-directory traversals."""
        cleaned = os.path.normpath(path.lstrip("/"))
        if cleaned.startswith("..") or "/.." in cleaned:
            raise ValueError("Path traversal is not permitted")
        return cleaned

    # -----------------------------------------------------------
    def list_folder(self, path):  # type: ignore[override]
        try:
            path = self._clean_path(path)
            items = self.backend.list_dir(path)
            return [self._jupyter_stat_to_attr(item) for item in items]
        except (JupyterBackendError, ValueError):
            return errno.ENOENT

    def stat(self, path):  # type: ignore[override]
        try:
            path = self._clean_path(path)
            # Try directory first
            items = self.backend.list_dir(path)
            model = {"name": path, "type": "directory", "size": 0}
        except JupyterBackendError:
            try:
                data = self.backend.get_file(path)
                model = {"name": path, "type": "file", "size": len(data)}
            except JupyterBackendError:
                return errno.ENOENT
        except ValueError:
            return errno.EPERM
        return self._jupyter_stat_to_attr(model)

    lstat = stat  # alias

    def open(self, path, flags, attr):  # type: ignore[override]
        try:
            path = self._clean_path(path)
        except ValueError:
            return errno.EPERM
        try:
            return JupyterSFTPHandle(flags, self.backend, path) 
        except JupyterBackendError:
            return errno.ENOENT

    # -----------------------------------------------------------
    # Additional SFTP verbs
    # -----------------------------------------------------------
    def remove(self, path):  # type: ignore[override]
        try:
            path = self._clean_path(path)
            self.backend.delete_path(path)
            return paramiko.SFTP_OK  # type: ignore[attr-defined]
        except (JupyterBackendError, ValueError):
            return errno.ENOENT

    def rename(self, oldpath, newpath):  # type: ignore[override]
        try:
            old_clean = self._clean_path(oldpath)
            new_clean = self._clean_path(newpath)
            self.backend.rename_path(old_clean, new_clean)
            return paramiko.SFTP_OK  # type: ignore[attr-defined]
        except (JupyterBackendError, ValueError):
            return errno.ENOENT

    def mkdir(self, path, attr):  # type: ignore[override]
        try:
            path = self._clean_path(path)
            self.backend.create_dir(path)
            return paramiko.SFTP_OK  # type: ignore[attr-defined]
        except (JupyterBackendError, ValueError):
            return errno.EPERM

    def rmdir(self, path):  # type: ignore[override]
        return self.remove(path)

    # Unsupported / stubbed operations
    def readlink(self, path):  # type: ignore[override]
        return errno.EOPNOTSUPP

    def symlink(self, target_path, path):  # type: ignore[override]
        return errno.EOPNOTSUPP

    def setstat(self, path, attr):  # type: ignore[override]
        return errno.EPERM

    def fsetstat(self, handle, attr):  # type: ignore[override]
        return errno.EPERM 