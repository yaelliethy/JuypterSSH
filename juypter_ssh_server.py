import argparse
import sys
from ssh_server import JuypterSSHServer

def parse_args():
    parser = argparse.ArgumentParser(
        description="JuypterSSH – expose a Jupyter kernel via SSH/SFTP"
    )
    parser.add_argument("--jupyter-url", required=True, help="Full Jupyter server URL (including token)")
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind the SSH server")
    parser.add_argument("--port", type=int, default=2222, help="Port to listen on for SSH connections")
    parser.add_argument("--host-key", default=None, help="Path to persist RSA host key (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose logging")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.debug:
        import os
        os.environ["JUYPTERSSH_DEBUG"] = "1"

    banner = "\U0001F680  JuypterSSH starting up..."
    print(banner)

    server = JuypterSSHServer(
        args.jupyter_url,
        host=args.host,
        port=args.port,
        host_key_path=args.host_key,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\U0001F44B  JuypterSSH stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main() 