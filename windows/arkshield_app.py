"""
ArkShield Desktop Application - Windows Version
Native desktop wrapper for ArkShield security monitoring dashboard
Uses Microsoft Edge WebView2 (no pythonnet required)
"""

import threading
import uvicorn
import sys
import os
import time
import socket
import subprocess
import webbrowser
from pathlib import Path

if getattr(sys, 'frozen', False):
    # Running as bundled exe
    # PyInstaller puts data files in a temporary folder accessed via sys._MEIPASS
    base_path = Path(sys._MEIPASS)
    src_path = base_path / "src"
    print(f"[ArkShield] Frozen mode - src_path: {src_path}")
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
        self.use_webview = False
        
        # Try to import webview (optional)
        try:
            import webview
            self.webview = webview
            self.use_webview = True
            print("[ArkShield] Using pywebview for native window")
        except ImportError:
            print("[ArkShield] pywebview not available, using Edge app mode")
            self.webview = None
        
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
    
    def open_in_edge_app_mode(self, url):
        """Open in Microsoft Edge app mode (no browser UI)"""
        edge_paths = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        
        edge_exe = None
        for path in edge_paths:
            if os.path.exists(path):
                edge_exe = path
                break
        
        if edge_exe:
            print(f"[ArkShield] Opening in Edge app mode...")
            subprocess.Popen([
                edge_exe,
                f"--app={url}",
                "--window-size=1400,900",
                "--disable-popup-blocking"
            ])
        else:
            print(f"[ArkShield] Edge not found, opening in default browser...")
            webbrowser.open(url)
    
    def run_with_webview(self, url):
        """Run with pywebview (native window)"""
        window = self.webview.create_window(
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
        self.webview.start(debug=False)
    
    def run(self):
        """Launch the desktop application"""
        # Start server in background thread
        self.server_thread = threading.Thread(target=self.start_server, daemon=True)
        self.server_thread.start()
        
        # Wait for server to be ready
        print("[ArkShield] Waiting for server to initialize...")
        time.sleep(3)
        
        # Create URL
        url = f"http://{self.host}:{self.port}"
        
        if self.use_webview:
            # Use pywebview native window
            try:
                self.run_with_webview(url)
            except Exception as e:
                print(f"[ArkShield] pywebview failed: {e}")
                print(f"[ArkShield] Falling back to Edge app mode...")
                self.open_in_edge_app_mode(url)
                # Keep server running
                try:
                    while True:
                        time.sleep(1)
                except KeyboardInterrupt:
                    pass
        else:
            # Use Edge app mode (looks native, no pythonnet required)
            self.open_in_edge_app_mode(url)
            
            print("\n" + "=" * 60)
            print("  ArkShield is running!")
            print("=" * 60)
            print(f"\n  URL: {url}")
            print("\n  Press Ctrl+C to stop the server")
            print("=" * 60 + "\n")
            
            # Keep server running
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[ArkShield] Shutting down...")
        
        sys.exit(0)


def main():
    """Main entry point"""
    print("=" * 60)
    print("  ArkShield Security Monitor - Desktop Application")
    print("  Windows Version")
    print("=" * 60)
    
    app = ArkShieldApp()
    app.run()


if __name__ == "__main__":
    main()
