"""
ArkShield Desktop Application - Linux Version
Native desktop wrapper for ArkShield security monitoring dashboard
"""

import webview
import threading
import uvicorn
import sys
import os
import time
import socket
from pathlib import Path

# Handle both development and PyInstaller bundled scenarios
if getattr(sys, 'frozen', False):
    # Running as bundled exe
    base_path = Path(sys._MEIPASS)
    src_path = base_path / "src"
    sys.path.insert(0, str(src_path))
else:
    # Running in development
    parent_dir = Path(__file__).resolve().parent.parent
    src_dir = parent_dir / "src"
    print(f"[ArkShield] Dev mode - src_dir: {src_dir}")
    sys.path.insert(0, str(src_dir))

# Import ArkShield core app
print("[ArkShield] Attempting to import arkshield.api.server...")
from arkshield.api.server import app
print("[ArkShield] Core app imported successfully")


class ArkShieldApp:
    """ArkShield Desktop Application Manager"""
    
    def __init__(self):
        self.server_thread = None
        self.server_running = False
        self.port = 8000
        self.host = "127.0.0.1"
        
    def find_free_port(self):
        """Find an available port if 8000 is taken"""
        for port in range(8000, 8100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.bind((self.host, port))
                sock.close()
                return port
            except OSError:
                continue
        return 8000
    
    def start_server(self):
        """Start FastAPI server in background thread"""
        self.port = self.find_free_port()
        
        config = uvicorn.Config(
            app=app,
            host=self.host,
            port=self.port,
            log_level="info",
            access_log=False
        )
        server = uvicorn.Server(config)
        
        print(f"[ArkShield] Starting server on {self.host}:{self.port}")
        self.server_running = True
        server.run()
    
    def run(self):
        """Launch the desktop application"""
        # Start server in background thread
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
        
        # Wait for server to be ready
        print("[ArkShield] Waiting for server to initialize...")
        time.sleep(3)
        
        # Create native window
        url = f"http://{self.host}:{self.port}"
        
        window = webview.create_window(
            title="ArkShield Security Monitor",
            url=url,
            width=1400,
            height=900,
            resizable=True,
            fullscreen=False,
            min_size=(1024, 768),
            background_color="#1a1a2e"
        )
        
        # Start webview (blocking call)
        # For Linux, use GTK backend
        webview.start(debug=False, gui='gtk')
        
        print("[ArkShield] Application closed")
        sys.exit(0)


def main():
    """Main entry point"""
    print("=" * 60)
    print("  ArkShield Security Monitor - Desktop Application")
    print("  Linux Version")
    print("=" * 60)
    
    app = ArkShieldApp()
    app.run()


if __name__ == "__main__":
    main()
