import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import socket
import threading
import select
from concurrent.futures import ThreadPoolExecutor
import socks
import time

class MultiProxyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Multi-Layer Proxy Tool")
        self.root.geometry("800x600")
        
        self.proxy_stack = []
        self.running = False
        self.thread_pool = ThreadPoolExecutor(max_workers=50)
        
        self.init_ui()
        self.init_proxy_options()
        
    def init_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Proxy Layers Configuration
        proxy_group = ttk.LabelFrame(main_frame, text="Configuração de Camadas de Proxy")
        proxy_group.pack(fill=tk.X, padx=5, pady=5)
        
        self.proxy_layers = []
        for i in range(3):
            layer_frame = ttk.Frame(proxy_group)
            layer_frame.pack(fill=tk.X, padx=5, pady=2)
            
            cb = ttk.Combobox(layer_frame, values=["SOCKS5", "Tor", "VPN"], width=10)
            cb.current(0)
            cb.pack(side=tk.LEFT, padx=5)
            
            host = ttk.Entry(layer_frame, width=20)
            host.insert(0, "Host")
            host.pack(side=tk.LEFT, padx=5)
            
            port = ttk.Entry(layer_frame, width=10)
            port.insert(0, "Porta")
            port.pack(side=tk.LEFT, padx=5)
            
            self.proxy_layers.append((cb, host, port))
        
        # Local Configuration
        local_group = ttk.LabelFrame(main_frame, text="Configuração Local")
        local_group.pack(fill=tk.X, padx=5, pady=5)
        
        self.local_port = ttk.Entry(local_group, width=10)
        self.local_port.insert(0, "8080")
        self.local_port.pack(padx=5, pady=5)
        
        # Controls
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.start_btn = ttk.Button(control_frame, text="Iniciar", command=self.start_proxy)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Parar", command=self.stop_proxy, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Logs
        logs_label = ttk.Label(main_frame, text="Logs:")
        logs_label.pack(anchor=tk.W, padx=5)
        
        self.logs = scrolledtext.ScrolledText(main_frame, height=10, state=tk.DISABLED)
        self.logs.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
    def init_proxy_options(self):
        self.proxy_layers[0][0].set("SOCKS5")
        self.proxy_layers[1][0].set("Tor")
        self.proxy_layers[2][0].set("VPN")
        
    def log(self, message):
        self.logs.config(state=tk.NORMAL)
        self.logs.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n")
        self.logs.config(state=tk.DISABLED)
        self.logs.yview(tk.END)
        
    def start_proxy(self):
        try:
            self.proxy_stack = []
            for layer in self.proxy_layers:
                cb, host, port = layer
                proxy_type = cb.get()
                
                if proxy_type == "Tor":
                    self.proxy_stack.append({'type': 'tor', 'host': '127.0.0.1', 'port': 9050})
                elif proxy_type == "SOCKS5":
                    self.proxy_stack.append({'type': 'socks5', 'host': host.get(), 'port': int(port.get())})
                elif proxy_type == "VPN":
                    self.proxy_stack.append({'type': 'vpn', 'host': host.get(), 'port': int(port.get())})
            
            self.running = True
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            local_port = int(self.local_port.get())
            threading.Thread(target=self.run_proxy, args=(local_port,), daemon=True).start()
            
            self.log("Proxy iniciado com sucesso!")
            self.log(f"Camadas: {[p['type'] for p in self.proxy_stack]}")
            
        except Exception as e:
            self.log(f"Erro ao iniciar proxy: {str(e)}")
            
    def stop_proxy(self):
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.log("Proxy parado")
        
    def run_proxy(self, local_port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', local_port))
        server_socket.listen(5)
        
        while self.running:
            try:
                client_socket, addr = server_socket.accept()
                self.thread_pool.submit(self.handle_client, client_socket)
            except Exception as e:
                if self.running:
                    self.log(f"Erro ao aceitar conexão: {str(e)}")
        
        server_socket.close()
        
    def handle_client(self, client_socket):
        try:
            current_socket = client_socket
            for proxy in reversed(self.proxy_stack):
                if proxy['type'] == 'tor' or proxy['type'] == 'socks5':
                    sock = socks.socksocket()
                    sock.setproxy(socks.PROXY_TYPE_SOCKS5, proxy['host'], proxy['port'])
                elif proxy['type'] == 'vpn':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((proxy['host'], proxy['port']))
                
                current_socket = sock
            
            self.redirect_traffic(client_socket, current_socket)
            
        except Exception as e:
            self.log(f"Erro no cliente: {str(e)}")
        finally:
            client_socket.close()
            if 'sock' in locals():
                sock.close()
                
    def redirect_traffic(self, src, dst):
        while self.running:
            readable, _, _ = select.select([src, dst], [], [], 1)
            for sock in readable:
                data = sock.recv(4096)
                if not data:
                    return
                target = dst if sock is src else src
                try:
                    target.sendall(data)
                except:
                    return

if __name__ == "__main__":
    root = tk.Tk()
    app = MultiProxyApp(root)
    root.mainloop()