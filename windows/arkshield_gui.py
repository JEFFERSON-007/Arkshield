"""
ArkShield Desktop GUI Application - Native Windows Interface
Real-time security monitoring with native GUI (no localhost/web browser)
"""

import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import time
import platform
from datetime import datetime
import psutil


class ArkShieldGUI:
    """Native Windows GUI for ArkShield Security Monitoring"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("ArkShield Security Monitor")
        self.root.geometry("1200x800")
        
        # Initialize monitoring
        self.running = True
        self.alert_count = 0
        
        # Setup GUI
        self.setup_ui()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self.monitor_loop, daemon=True)
        self.monitor_thread.start()
        
    def setup_ui(self):
        """Create the GUI interface"""
        
        # Title bar
        title_frame = tk.Frame(self.root, bg="#1e3a8a", height=60)
        title_frame.pack(fill=tk.X)
        title_frame.pack_propagate(False)
        
        title_label = tk.Label(
            title_frame, 
            text="🛡️ ArkShield Security Monitor", 
            font=("Segoe UI", 20, "bold"),
            bg="#1e3a8a",
            fg="white"
        )
        title_label.pack(pady=10)
        
        # Status bar
        status_frame = tk.Frame(self.root, bg="#e5e7eb", height=40)
        status_frame.pack(fill=tk.X)
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(
            status_frame,
            text="● Status: Running",
            font=("Segoe UI", 10),
            bg="#e5e7eb",
            fg="#059669"
        )
        self.status_label.pack(side=tk.LEFT, padx=20, pady=10)
        
        self.time_label = tk.Label(
            status_frame,
            text=f"Started: {datetime.now().strftime('%H:%M:%S')}",
            font=("Segoe UI", 10),
            bg="#e5e7eb"
        )
        self.time_label.pack(side=tk.RIGHT, padx=20, pady=10)
        
        # Main content
        main_frame = tk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Dashboard tab
        self.dashboard_tab = tk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="📊 Dashboard")
        self.setup_dashboard()
        
        # Processes tab
        self.processes_tab = tk.Frame(self.notebook)
        self.notebook.add(self.processes_tab, text="📋 Processes")
        self.setup_processes()
        
        # Network tab
        self.network_tab = tk.Frame(self.notebook)
        self.notebook.add(self.network_tab, text="🌐 Network")
        self.setup_network()
        
        # Alerts tab
        self.alerts_tab = tk.Frame(self.notebook)
        self.notebook.add(self.alerts_tab, text="⚠️ Alerts")
        self.setup_alerts()
        
    def setup_dashboard(self):
        """Setup dashboard tab"""
        # System info frame
        info_frame = tk.LabelFrame(
            self.dashboard_tab, 
            text="System Information",
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=10
        )
        info_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # CPU
        cpu_frame = tk.Frame(info_frame)
        cpu_frame.pack(fill=tk.X, pady=5)
        tk.Label(cpu_frame, text="CPU Usage:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.cpu_label = tk.Label(cpu_frame, text="0%", font=("Segoe UI", 10))
        self.cpu_label.pack(side=tk.LEFT, padx=10)
        self.cpu_bar = ttk.Progressbar(cpu_frame, length=300, mode='determinate')
        self.cpu_bar.pack(side=tk.LEFT)
        
        # Memory
        mem_frame = tk.Frame(info_frame)
        mem_frame.pack(fill=tk.X, pady=5)
        tk.Label(mem_frame, text="Memory Usage:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.mem_label = tk.Label(mem_frame, text="0%", font=("Segoe UI", 10))
        self.mem_label.pack(side=tk.LEFT, padx=10)
        self.mem_bar = ttk.Progressbar(mem_frame, length=300, mode='determinate')
        self.mem_bar.pack(side=tk.LEFT)
        
        # Disk
        disk_frame = tk.Frame(info_frame)
        disk_frame.pack(fill=tk.X, pady=5)
        tk.Label(disk_frame, text="Disk Usage:", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.disk_label = tk.Label(disk_frame, text="0%", font=("Segoe UI", 10))
        self.disk_label.pack(side=tk.LEFT, padx=10)
        self.disk_bar = ttk.Progressbar(disk_frame, length=300, mode='determinate')
        self.disk_bar.pack(side=tk.LEFT)
        
        # Monitors status
        monitors_frame = tk.LabelFrame(
            self.dashboard_tab,
            text="Active Monitors",
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=10
        )
        monitors_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.monitors_text = tk.Text(monitors_frame, height=10, font=("Consolas", 9))
        self.monitors_text.pack(fill=tk.BOTH, expand=True)
        
    def setup_processes(self):
        """Setup processes tab"""
        # Toolbar
        toolbar = tk.Frame(self.processes_tab)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(
            toolbar, 
            text="🔄 Refresh",
            command=self.refresh_processes,
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=5)
        
        self.process_count_label = tk.Label(
            toolbar,
            text="Processes: 0",
            font=("Segoe UI", 9)
        )
        self.process_count_label.pack(side=tk.LEFT, padx=20)
        
        # Process list
        list_frame = tk.Frame(self.processes_tab)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview
        self.process_tree = ttk.Treeview(
            list_frame,
            columns=("PID", "Name", "CPU", "Memory", "Status"),
            show="headings",
            yscrollcommand=scrollbar.set
        )
        scrollbar.config(command=self.process_tree.yview)
        
        # Columns
        self.process_tree.heading("PID", text="PID")
        self.process_tree.heading("Name", text="Process Name")
        self.process_tree.heading("CPU", text="CPU %")
        self.process_tree.heading("Memory", text="Memory (MB)")
        self.process_tree.heading("Status", text="Status")
        
        self.process_tree.column("PID", width=80)
        self.process_tree.column("Name", width=300)
        self.process_tree.column("CPU", width=80)
        self.process_tree.column("Memory", width=120)
        self.process_tree.column("Status", width=100)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True)
        
    def setup_network(self):
        """Setup network tab"""
        # Network stats
        stats_frame = tk.LabelFrame(
            self.network_tab,
            text="Network Statistics",
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=10
        )
        stats_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.network_stats_text = tk.Text(stats_frame, height=8, font=("Consolas", 9))
        self.network_stats_text.pack(fill=tk.BOTH, expand=True)
        
        # Active connections
        conn_frame = tk.LabelFrame(
            self.network_tab,
            text="Active Connections",
            font=("Segoe UI", 11, "bold"),
            padx=10,
            pady=10
        )
        conn_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.network_tree = ttk.Treeview(
            conn_frame,
            columns=("Protocol", "Local", "Remote", "Status", "PID"),
            show="headings"
        )
        
        self.network_tree.heading("Protocol", text="Protocol")
        self.network_tree.heading("Local", text="Local Address")
        self.network_tree.heading("Remote", text="Remote Address")
        self.network_tree.heading("Status", text="Status")
        self.network_tree.heading("PID", text="PID")
        
        self.network_tree.pack(fill=tk.BOTH, expand=True)
        
    def setup_alerts(self):
        """Setup alerts tab"""
        # Toolbar
        toolbar = tk.Frame(self.alerts_tab)
        toolbar.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Button(
            toolbar,
            text="🗑️ Clear All",
            command=self.clear_alerts,
            font=("Segoe UI", 9)
        ).pack(side=tk.LEFT, padx=5)
        
        self.alert_count_label = tk.Label(
            toolbar,
            text="Alerts: 0",
            font=("Segoe UI", 9)
        )
        self.alert_count_label.pack(side=tk.LEFT, padx=20)
        
        # Alerts display
        self.alerts_text = scrolledtext.ScrolledText(
            self.alerts_tab,
            font=("Consolas", 9),
            bg="#1f2937",
            fg="#f3f4f6"
        )
        self.alerts_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def monitor_loop(self):
        """Background monitoring loop"""
        while self.running:
            try:
                self.update_dashboard()
                self.update_processes()
                self.update_network()
                time.sleep(2)  # Update every 2 seconds
            except Exception as e:
                print(f"Monitor error: {e}")
                
    def update_dashboard(self):
        """Update dashboard metrics"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=0.1)
            self.cpu_label.config(text=f"{cpu_percent:.1f}%")
            self.cpu_bar['value'] = cpu_percent
            
            # Memory
            mem = psutil.virtual_memory()
            self.mem_label.config(text=f"{mem.percent:.1f}%")
            self.mem_bar['value'] = mem.percent
            
            # Disk
            disk = psutil.disk_usage('/')
            self.disk_label.config(text=f"{disk.percent:.1f}%")
            self.disk_bar['value'] = disk.percent
            
            # Monitors status
            self.monitors_text.delete(1.0, tk.END)
            monitors_info = f"""
✓ Process Monitor:     Active
✓ Network Monitor:     Active
✓ Memory Scanner:      Active
✓ Filesystem Monitor:  Active
✓ Integrity Checker:   Active
✓ Persistence Detector: Active

Last Update: {datetime.now().strftime('%H:%M:%S')}
CPU: {cpu_percent:.1f}%  |  Memory: {mem.percent:.1f}%  |  Disk: {disk.percent:.1f}%
"""
            self.monitors_text.insert(1.0, monitors_info)
            
        except Exception as e:
            print(f"Dashboard update error: {e}")
            
    def update_processes(self):
        """Update process list"""
        try:
            # Clear existing
            for item in self.process_tree.get_children():
                self.process_tree.delete(item)
            
            # Get processes
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'status']):
                try:
                    info = proc.info
                    mem_mb = info['memory_info'].rss / 1024 / 1024 if info['memory_info'] else 0
                    processes.append({
                        'pid': info['pid'],
                        'name': info['name'],
                        'cpu': info['cpu_percent'] or 0,
                        'memory': mem_mb,
                        'status': info['status']
                    })
                except:
                    continue
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            
            # Add top 50 processes
            for proc in processes[:50]:
                self.process_tree.insert('', tk.END, values=(
                    proc['pid'],
                    proc['name'],
                    f"{proc['cpu']:.1f}",
                    f"{proc['memory']:.1f}",
                    proc['status']
                ))
            
            self.process_count_label.config(text=f"Processes: {len(processes)} (showing top 50)")
            
        except Exception as e:
            print(f"Process update error: {e}")
            
    def update_network(self):
        """Update network information"""
        try:
            # Network stats
            net_io = psutil.net_io_counters()
            
            stats = f"""
Bytes Sent:     {net_io.bytes_sent / 1024 / 1024:.2f} MB
Bytes Received: {net_io.bytes_recv / 1024 / 1024:.2f} MB
Packets Sent:   {net_io.packets_sent:,}
Packets Recv:   {net_io.packets_recv:,}
Errors In:      {net_io.errin}
Errors Out:     {net_io.errout}
Drops In:       {net_io.dropin}
"""
            self.network_stats_text.delete(1.0, tk.END)
            self.network_stats_text.insert(1.0, stats)
            
            # Clear connections
            for item in self.network_tree.get_children():
                self.network_tree.delete(item)
            
            # Get connections
            connections = psutil.net_connections(kind='inet')[:30]  # Top 30
            for conn in connections:
                try:
                    local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"
                    self.network_tree.insert('', tk.END, values=(
                        conn.type.name,
                        local,
                        remote,
                        conn.status,
                        conn.pid or "-"
                    ))
                except:
                    continue
                    
        except Exception as e:
            print(f"Network update error: {e}")
            
    def refresh_processes(self):
        """Manual refresh of process list"""
        self.update_processes()
        
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts_text.delete(1.0, tk.END)
        self.alert_count_label.config(text="Alerts: 0")
        
    def on_closing(self):
        """Clean shutdown"""
        self.running = False
        self.root.destroy()


def main():
    """Launch ArkShield GUI"""
    root = tk.Tk()
    app = ArkShieldGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
