import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import select
import subprocess
from concurrent.futures import ThreadPoolExecutor
import socks
import time
import json
import random
import re
from collections import deque

class TerminalText(tk.Text):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.config(
            bg='#001100',
            fg='#00ff00',
            insertbackground='#00ff00',
            selectbackground='#003300',
            font=('Courier New', 10),
            relief=tk.FLAT
        )
        self.tag_configure('error', foreground='#ff0000')
        self.tag_configure('warning', foreground='#ffff00')
        self.tag_configure('success', foreground='#00ff00')
        self.tag_configure('debug', foreground='#006600')

class TrafficInspector:
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
        'Googlebot/2.1 (+http://www.google.com/bot.html)',
        'curl/7.68.0'
    ]
    
    def __init__(self):
        self.active_spoofs = {}
        self.sniff_enabled = False
        self.spoof_enabled = False
        
    def should_inspect(self, data):
        return b'HTTP/' in data and b'User-Agent:' in data
    
    def spoof_user_agent(self, data):
        new_agent = random.choice(self.USER_AGENTS)
        return re.sub(
            rb'User-Agent:.*?\r\n',
            f'User-Agent: {new_agent}\r\n'.encode(),
            data,
            count=1
        )
        
    def log_traffic(self, data):
        if self.sniff_enabled and len(data) > 0:
            with open('.traffic.log', 'a') as f:
                f.write(f"[{time.time()}] {data[:200].hex()}\n")

class MultiProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DEEP LAYER v1.3.37")
        self.root.geometry("800x600")
        self.set_dark_theme()

        self.proxy_stack = []
        self.running = False
        self.active_connections = []
        self.thread_pool = ThreadPoolExecutor(max_workers=50)
        self.vpn_process = None
        self.inspector = TrafficInspector()
        self.hidden_features = False

        self.init_ui()
        self.init_proxy_options()
        self.root.bind("<Control-g>", lambda e: self.toggle_stealth())
        self.root.bind("<Control-Alt-u>", lambda e: self.toggle_advanced_mode())
        self.sniff_history = deque(maxlen=50)
        self.spoof_counter = 0
        self.init_monitor_panel()
        
    def init_monitor_panel(self):
        # Painel de monitoramento estilo terminal
        monitor_frame = ttk.LabelFrame(self.root, text=":: LIVE MONITOR ::")
        monitor_frame.pack(fill=tk.X, padx=5, pady=5)

        # Contadores
        self.spoof_label = ttk.Label(monitor_frame, text="SPOOF: 0", foreground="#00ff00")
        self.spoof_label.pack(side=tk.LEFT, padx=10)
        
        self.sniff_label = ttk.Label(monitor_frame, text="SNIFF: 0KB", foreground="#00ff00")
        self.sniff_label.pack(side=tk.LEFT, padx=10)

        # Gráfico de tráfego ASCII
        self.traffic_graph = ttk.Label(monitor_frame, text="[||....................]", width=30)
        self.traffic_graph.pack(side=tk.RIGHT, padx=10)

        # Atualização periódica
        self.update_monitor()

    def update_monitor(self):
        # Atualiza os contadores
        self.spoof_label.config(text=f"AGENT: {self.spoof_counter}")
        
        total_kb = sum(len(pkt) for pkt in self.sniff_history) // 1024
        self.sniff_label.config(text=f"TRAF: {total_kb}KB")
        
        # Atualiza gráfico estilo terminal
        traffic_level = min(len(self.sniff_history), 20)
        self.traffic_graph.config(text=f"[{'|'*traffic_level}{'.'*(20-traffic_level)}]")
        
        # Agenda próxima atualização
        self.root.after(1000, self.update_monitor)

    def set_dark_theme(self):
        self.root.configure(bg='#000000')
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('.', background='#001100', foreground='#00ff00',
                        fieldbackground='#002200', insertcolor='#00ff00')
        style.map('TCombobox',
                  fieldbackground=[('readonly', '#002200')],
                  selectbackground=[('!focus', '#003300')],
                  selectforeground=[('!focus', '#00ff00')])

    def toggle_hidden_features(self):
        self.hidden_features = not self.hidden_features
        status = "ENABLED" if self.hidden_features else "DISABLED"
        self.log(f"Shadow features {status}", 'warning')

    def init_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        proxy_group = ttk.LabelFrame(main_frame, text=":: PROXY LAYERS ::")
        proxy_group.pack(fill=tk.X, padx=5, pady=5)

        self.proxy_layers = []
        for i in range(3):
            layer_frame = ttk.Frame(proxy_group)
            layer_frame.pack(fill=tk.X, padx=5, pady=2)

            cb = ttk.Combobox(layer_frame, values=["SOCKS5", "Tor", "VPN"], width=8)
            cb.current(0)
            cb.pack(side=tk.LEFT, padx=2)

            ttk.Label(layer_frame, text="HOST:", width=5).pack(side=tk.LEFT)
            host = ttk.Entry(layer_frame, width=20)
            host.pack(side=tk.LEFT, padx=2)

            ttk.Label(layer_frame, text="PORT:", width=5).pack(side=tk.LEFT)
            port = ttk.Entry(layer_frame, width=8)
            port.pack(side=tk.LEFT, padx=2)

            ttk.Label(layer_frame, text="USER:", width=5).pack(side=tk.LEFT)
            user = ttk.Entry(layer_frame, width=10)
            user.pack(side=tk.LEFT, padx=2)

            ttk.Label(layer_frame, text="PASS:", width=5).pack(side=tk.LEFT)
            password = ttk.Entry(layer_frame, width=10, show="*")
            password.pack(side=tk.LEFT, padx=2)

            self.proxy_layers.append((cb, host, port, user, password))

        local_group = ttk.LabelFrame(main_frame, text=":: LOCAL GATEWAY ::")
        local_group.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(local_group, text="PORT:").pack(side=tk.LEFT)
        self.local_port = ttk.Entry(local_group, width=8)
        self.local_port.insert(0, "8080")
        self.local_port.pack(side=tk.LEFT, padx=5)

        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)

        self.start_btn = ttk.Button(control_frame, text="START", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=2)

        self.stop_btn = ttk.Button(control_frame, text="KILL", command=self.stop_proxy, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        self.stealth_btn = ttk.Button(control_frame, text="GHOST MODE", command=self.toggle_stealth)
        self.stealth_btn.pack(side=tk.RIGHT, padx=2)

        self.save_btn = ttk.Button(control_frame, text="SAVE", command=self.save_config)
        self.save_btn.pack(side=tk.LEFT, padx=2)

        self.load_btn = ttk.Button(control_frame, text="LOAD", command=self.load_config)
        self.load_btn.pack(side=tk.LEFT, padx=2)

        self.vpn_btn = ttk.Button(control_frame, text="START VPN", command=self.start_vpn)
        self.vpn_btn.pack(side=tk.LEFT, padx=2)

        logs_label = ttk.Label(main_frame, text=":: SYSTEM LOGS ::")
        logs_label.pack(anchor=tk.W, padx=5)

        self.logs = TerminalText(main_frame, height=10)
        scroll = ttk.Scrollbar(main_frame, command=self.logs.yview)
        self.logs.configure(yscrollcommand=scroll.set)
        self.logs.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        adv_control_frame = ttk.Frame(main_frame)
        adv_control_frame.pack(fill=tk.X, padx=5, pady=2)

        self.sniff_btn = ttk.Button(adv_control_frame, text="📡", width=3,
                                  command=self.toggle_sniffer)
        self.sniff_btn.pack(side=tk.LEFT, padx=2)
        ToolTip(self.sniff_btn, "Network Sniffer [OFF]")

        self.spoof_btn = ttk.Button(adv_control_frame, text="🎭", width=3,
                                  command=self.toggle_spoofing)
        self.spoof_btn.pack(side=tk.LEFT, padx=2)
        ToolTip(self.spoof_btn, "Agent Spoofer [OFF]")
        
        
    def toggle_advanced_mode(self):
        self.hidden_features = not self.hidden_features
        if self.hidden_features:
            self.sniff_btn.configure(state=tk.NORMAL)
            self.spoof_btn.configure(state=tk.NORMAL)
            self.log("Advanced mode unlocked", 'warning')
        else:
            self.sniff_btn.configure(state=tk.DISABLED)
            self.spoof_btn.configure(state=tk.DISABLED)
            self.log("Advanced mode disabled", 'warning')

    def toggle_sniffer(self):
        self.inspector.sniff_enabled = not self.inspector.sniff_enabled
        status = "ON" if self.inspector.sniff_enabled else "OFF"
        ToolTip(self.sniff_btn, f"Network Sniffer [{status}]")
        self.log(f"Packet sniffer {status}", 'sniff')

    def toggle_spoofing(self):
        self.inspector.spoof_enabled = not self.inspector.spoof_enabled
        status = "ON" if self.inspector.spoof_enabled else "OFF"
        ToolTip(self.spoof_btn, f"Agent Spoofer [{status}]")
        self.log(f"User-Agent spoofing {status}", 'spoof')

    def init_proxy_options(self):
        self.proxy_layers[0][0].set("SOCKS5")
        self.proxy_layers[1][0].set("Tor")
        self.proxy_layers[2][0].set("VPN")

    def log(self, message, category='info'):
        self.logs.config(state=tk.NORMAL)
        self.logs.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] ", 'time')
        self.logs.insert(tk.END, f"{message}\n", category)
        self.logs.config(state=tk.DISABLED)
        self.logs.yview(tk.END)

    def start_proxy(self):
        try:
            self.proxy_stack = []
            for layer in self.proxy_layers:
                cb, host, port, user, password = layer
                if not host.get() or not port.get().isdigit():
                    continue
                self.proxy_stack.append({
                    'type': cb.get().lower(),
                    'host': host.get(),
                    'port': int(port.get()),
                    'user': user.get(),
                    'pass': password.get()
                })

            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)

            local_port = int(self.local_port.get())
            threading.Thread(target=self.run_proxy, args=(local_port,), daemon=True).start()

            self.log("Proxy chain initialized", 'success')
            self.log(f"Active layers: {[p['type'] for p in self.proxy_stack]}", 'debug')

        except Exception as e:
            self.log(f"Initialization failed: {str(e)}", 'error')
            messagebox.showerror("SYSTEM ERROR", str(e))

    def stop_proxy(self):
        self.running = False
        for conn in self.active_connections:
            try: conn.close()
            except: pass
        self.active_connections.clear()
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Network termination completed", 'warning')

    def run_proxy(self, local_port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', local_port))
        server_socket.listen(5)

        self.log(f"Listening on port {local_port}", 'success')
        while self.running:
            try:
                client_socket, addr = server_socket.accept()
                self.active_connections.append(client_socket)
                self.thread_pool.submit(self.handle_client, client_socket)
                self.log(f"Incoming connection from {addr[0]}", 'debug')
            except Exception as e:
                if self.running:
                    self.log(f"Connection error: {str(e)}", 'error')

        server_socket.close()

    def handle_client(self, client_socket):
        try:
            current_socket = client_socket
            for proxy in reversed(self.proxy_stack):
                if proxy['type'] in ('tor', 'socks5'):
                    sock = socks.socksocket()
                    if proxy['user'] and proxy['pass']:
                        sock.set_proxy(socks.SOCKS5, proxy['host'], proxy['port'], True, proxy['user'], proxy['pass'])
                    else:
                        sock.set_proxy(socks.SOCKS5, proxy['host'], proxy['port'])
                    sock.connect(('example.com', 80))
                    current_socket = sock
                elif proxy['type'] == 'vpn':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((proxy['host'], proxy['port']))
                    current_socket = sock

            self.redirect_traffic(client_socket, current_socket)

        except Exception as e:
            self.log(f"Connection failure: {str(e)}", 'error')
        finally:
            client_socket.close()
            if client_socket in self.active_connections:
                self.active_connections.remove(client_socket)

    def redirect_traffic(self, src, dst):
        while self.running:
            readable, _, _ = select.select([src, dst], [], [], 1)
            for sock in readable:
                try:
                    data = sock.recv(4096)
                    if not data:
                        return

                    # Spoof
                    if self.inspector.spoof_enabled and self.inspector.should_inspect(data):
                        data = self.inspector.spoof_user_agent(data)
                        self.spoof_counter += 1
                        self.log(f"Agent spoofed: {self.spoof_counter}", 'spoof')

                    # Sniff
                    if self.inspector.sniff_enabled:
                        self.sniff_history.append(data)
                        self.log(f"Packet: {len(data)}B", 'sniff')

                    target = dst if sock is src else src
                    target.sendall(data)
                except:
                    return

    def toggle_stealth(self):
        if self.root.state() == 'normal':
            self.root.withdraw()
            self.log("Ghost mode activated", 'warning')
        else:
            self.root.deiconify()
            self.root.lift()
            self.log("Returning to visible mode", 'success')

    def save_config(self):
        config = []
        for cb, host, port, user, password in self.proxy_layers:
            config.append({
                "type": cb.get(),
                "host": host.get(),
                "port": port.get(),
                "user": user.get(),
                "pass": password.get()
            })
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            with open(path, 'w') as f:
                json.dump(config, f)
            self.log("Configuration saved", 'success')

    def load_config(self):
        path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if path:
            with open(path, 'r') as f:
                config = json.load(f)
            for i, entry in enumerate(config):
                if i < len(self.proxy_layers):
                    cb, host, port, user, password = self.proxy_layers[i]
                    cb.set(entry["type"])
                    host.delete(0, tk.END)
                    host.insert(0, entry["host"])
                    port.delete(0, tk.END)
                    port.insert(0, str(entry["port"]))
                    user.delete(0, tk.END)
                    user.insert(0, entry["user"])
                    password.delete(0, tk.END)
                    password.insert(0, entry["pass"])
            self.log("Configuration loaded", 'success')

    def start_vpn(self):
        path = filedialog.askopenfilename(filetypes=[("OpenVPN Config", "*.ovpn")])
        if path:
            try:
                self.vpn_process = subprocess.Popen(['sudo', 'openvpn', '--config', path])
                self.log("VPN process started", 'success')
                if self.hidden_features:
                    self.inspector.sniff_enabled = True
                    self.inspector.spoof_enabled = True
            except Exception as e:
                self.log(f"Failed to start VPN: {e}", 'error')
                
                
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.bind("<Enter>", self.enter)
        self.widget.bind("<Leave>", self.close)

    def enter(self, event=None):
        x, y, _, _ = self.widget.bbox("insert")
        x += self.widget.winfo_rootx() + 25
        y += self.widget.winfo_rooty() + 25
        
        self.tw = tk.Toplevel(self.widget)
        self.tw.wm_overrideredirect(True)
        self.tw.wm_geometry(f"+{x}+{y}")
        
        label = ttk.Label(self.tw, text=self.text, background="#003300",
                         foreground="#00ff00", relief='solid', borderwidth=1)
        label.pack()

    def close(self, event=None):
        if hasattr(self, 'tw'):
            self.tw.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = MultiProxyApp(root)
    root.mainloop()