import sys
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
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit, QScrollArea,
    QFileDialog, QMessageBox, QFrame, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QTextCursor, QFont, QTextCharFormat, QPalette

class TerminalText(QTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            background-color: #001100;
            color: #00ff00;
            border: 1px solid #003300;
            font-family: 'Courier New';
            font-size: 10pt;
        """)
        self.setReadOnly(True)
        
        self.formats = {
            'info': self.create_format('#00ff00'),
            'error': self.create_format('#ff0000'),
            'warning': self.create_format('#ffff00'),
            'success': self.create_format('#00ff00'),
            'debug': self.create_format('#006600'),
            'sniff': self.create_format('#00ffff'),
            'spoof': self.create_format('#ff00ff'),
            'time': self.create_format('#00cc00'),
        }
    
    def create_format(self, color):
        fmt = QTextCharFormat()
        fmt.setForeground(QColor(color))
        return fmt
    
    def log(self, message, category='info'):
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(f"[{time.strftime('%H:%M:%S')}] ", self.formats['time'])
        cursor.insertText(f"{message}\n", self.formats.get(category, self.formats['info']))
        self.setTextCursor(cursor)
        self.ensureCursorVisible()

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.widget.setToolTip(self.text)

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

class MultiProxyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEEP LAYER v1.0.1")
        self.setGeometry(100, 100, 800, 600)
        self.setup_ui()
        self.setup_styles()
        
        self.proxy_stack = []
        self.running = False
        self.active_connections = []
        self.thread_pool = ThreadPoolExecutor(max_workers=50)
        self.vpn_process = None
        self.inspector = TrafficInspector()
        self.hidden_features = False
        self.sniff_history = deque(maxlen=50)
        self.spoof_counter = 0
        
        self.init_proxy_options()
        
        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self.update_monitor)
        self.monitor_timer.start(1000)
        
    def setup_styles(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QGroupBox {
                color: #00ff00;
                border: 1px solid #003300;
                margin-top: 1ex;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 3px 0 3px;
            }
            QLabel {
                color: #00ff00;
            }
            QLineEdit, QComboBox {
                background-color: #002200;
                color: #00ff00;
                border: 1px solid #003300;
                padding: 2px;
            }
            QPushButton {
                background-color: #002200;
                color: #00ff00;
                border: 1px solid #003300;
                padding: 5px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #003300;
                border: 1px solid #00ff00;
            }
            QPushButton:disabled {
                background-color: #001100;
                color: #006600;
            }
            QTextEdit {
                background-color: #001100;
                color: #00ff00;
                border: 1px solid #003300;
                font-family: 'Courier New';
                font-size: 10pt;
            }
            QScrollBar:vertical {
                background: #001100;
                width: 12px;
            }
            QScrollBar::handle:vertical {
                background: #003300;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                background: none;
            }
        """)
        
    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Painel de monitoramento
        monitor_frame = QFrame()
        monitor_frame.setFrameShape(QFrame.Shape.StyledPanel)
        monitor_layout = QHBoxLayout(monitor_frame)
        
        self.spoof_label = QLabel("SPOOF: 0")
        self.spoof_label.setStyleSheet("color: #00ff00;")
        monitor_layout.addWidget(self.spoof_label)
        
        self.sniff_label = QLabel("SNIFF: 0KB")
        self.sniff_label.setStyleSheet("color: #00ff00;")
        monitor_layout.addWidget(self.sniff_label)
        
        self.traffic_graph = QLabel("[||....................]")
        self.traffic_graph.setStyleSheet("color: #00ff00; font-family: 'Courier New';")
        self.traffic_graph.setAlignment(Qt.AlignmentFlag.AlignRight)
        monitor_layout.addWidget(self.traffic_graph)
        
        main_layout.addWidget(monitor_frame)
        
        # Grupo de camadas de proxy
        proxy_group = QGroupBox(":: PROXY LAYERS ::")
        proxy_layout = QVBoxLayout(proxy_group)
        
        self.proxy_layers = []
        for _ in range(3):
            layer_frame = QWidget()
            layer_layout = QHBoxLayout(layer_frame)
            layer_layout.setContentsMargins(5, 5, 5, 5)
            
            cb = QComboBox()
            cb.addItems(["SOCKS5", "Tor", "VPN"])
            cb.setFixedWidth(100)
            layer_layout.addWidget(cb)
            
            layer_layout.addWidget(QLabel("HOST:"))
            host = QLineEdit()
            host.setFixedWidth(150)
            layer_layout.addWidget(host)
            
            layer_layout.addWidget(QLabel("PORT:"))
            port = QLineEdit()
            port.setFixedWidth(60)
            layer_layout.addWidget(port)
            
            layer_layout.addWidget(QLabel("USER:"))
            user = QLineEdit()
            user.setFixedWidth(80)
            layer_layout.addWidget(user)
            
            layer_layout.addWidget(QLabel("PASS:"))
            password = QLineEdit()
            password.setEchoMode(QLineEdit.EchoMode.Password)
            password.setFixedWidth(80)
            layer_layout.addWidget(password)
            
            proxy_layout.addWidget(layer_frame)
            self.proxy_layers.append((cb, host, port, user, password))
        
        main_layout.addWidget(proxy_group)
        
        # Grupo de gateway local
        local_group = QGroupBox(":: LOCAL GATEWAY ::")
        local_layout = QHBoxLayout(local_group)
        local_layout.addWidget(QLabel("PORT:"))
        
        self.local_port = QLineEdit("8080")
        self.local_port.setFixedWidth(60)
        local_layout.addWidget(self.local_port)
        local_layout.addStretch()
        
        main_layout.addWidget(local_group)
        
        # Painel de controle
        control_frame = QWidget()
        control_layout = QHBoxLayout(control_frame)
        control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.start_btn = QPushButton("START")
        self.start_btn.clicked.connect(self.start_proxy)
        control_layout.addWidget(self.start_btn)
        
        self.stop_btn = QPushButton("KILL")
        self.stop_btn.clicked.connect(self.stop_proxy)
        self.stop_btn.setEnabled(False)
        control_layout.addWidget(self.stop_btn)
        
        self.save_btn = QPushButton("SAVE")
        self.save_btn.clicked.connect(self.save_config)
        control_layout.addWidget(self.save_btn)
        
        self.load_btn = QPushButton("LOAD")
        self.load_btn.clicked.connect(self.load_config)
        control_layout.addWidget(self.load_btn)
        
        self.vpn_btn = QPushButton("START VPN")
        self.vpn_btn.clicked.connect(self.start_vpn)
        control_layout.addWidget(self.vpn_btn)
        
        control_layout.addStretch()
        
        self.stealth_btn = QPushButton("GHOST MODE")
        self.stealth_btn.clicked.connect(self.toggle_stealth)
        control_layout.addWidget(self.stealth_btn)
        
        main_layout.addWidget(control_frame)
        
        # Painel de controle avançado
        adv_control_frame = QWidget()
        adv_control_layout = QHBoxLayout(adv_control_frame)
        adv_control_layout.setContentsMargins(0, 0, 0, 0)
        
        self.sniff_btn = QPushButton("📡")
        self.sniff_btn.setFixedWidth(40)
        self.sniff_btn.clicked.connect(self.toggle_sniffer)
        self.sniff_btn.setEnabled(False)
        ToolTip(self.sniff_btn, "Network Sniffer [OFF]")
        adv_control_layout.addWidget(self.sniff_btn)
        
        self.spoof_btn = QPushButton("🎭")
        self.spoof_btn.setFixedWidth(40)
        self.spoof_btn.clicked.connect(self.toggle_spoofing)
        self.spoof_btn.setEnabled(False)
        ToolTip(self.spoof_btn, "Agent Spoofer [OFF]")
        adv_control_layout.addWidget(self.spoof_btn)
        
        adv_control_layout.addStretch()
        
        main_layout.addWidget(adv_control_frame)
        
        # Logs do sistema
        logs_label = QLabel(":: SYSTEM LOGS ::")
        logs_label.setStyleSheet("font-weight: bold; color: #00ff00;")
        main_layout.addWidget(logs_label)
        
        self.logs = TerminalText()
        main_layout.addWidget(self.logs)
        
        self.installEventFilter(self)
    
    def eventFilter(self, obj, event):
        if event.type() == event.Type.KeyPress:
            if event.key() == Qt.Key.Key_G and (event.modifiers() & Qt.KeyboardModifier.ControlModifier):
                self.toggle_stealth()
                return True
            elif event.key() == Qt.Key.Key_U and (event.modifiers() & Qt.KeyboardModifier.ControlModifier) and (event.modifiers() & Qt.KeyboardModifier.AltModifier):
                self.toggle_advanced_mode()
                return True
        return super().eventFilter(obj, event)
    
    def init_proxy_options(self):
        self.proxy_layers[0][0].setCurrentText("SOCKS5")
        self.proxy_layers[1][0].setCurrentText("Tor")
        self.proxy_layers[2][0].setCurrentText("VPN")
    
    def update_monitor(self):
        self.spoof_label.setText(f"AGENT: {self.spoof_counter}")
        total_kb = sum(len(pkt) for pkt in self.sniff_history) // 1024
        self.sniff_label.setText(f"TRAF: {total_kb}KB")
        traffic_level = min(len(self.sniff_history), 20)
        self.traffic_graph.setText(f"[{'|'*traffic_level}{'.'*(20-traffic_level)}]")
    
    def toggle_advanced_mode(self):
        self.hidden_features = not self.hidden_features
        self.sniff_btn.setEnabled(self.hidden_features)
        self.spoof_btn.setEnabled(self.hidden_features)
        status = "unlocked" if self.hidden_features else "disabled"
        self.logs.log(f"Advanced mode {status}", 'warning')
    
    def toggle_sniffer(self):
        self.inspector.sniff_enabled = not self.inspector.sniff_enabled
        status = "ON" if self.inspector.sniff_enabled else "OFF"
        self.sniff_btn.setToolTip(f"Network Sniffer [{status}]")
        self.logs.log(f"Packet sniffer {status}", 'sniff')
    
    def toggle_spoofing(self):
        self.inspector.spoof_enabled = not self.inspector.spoof_enabled
        status = "ON" if self.inspector.spoof_enabled else "OFF"
        self.spoof_btn.setToolTip(f"Agent Spoofer [{status}]")
        self.logs.log(f"User-Agent spoofing {status}", 'spoof')
    
    def start_proxy(self):
        try:
            self.proxy_stack = []
            for layer in self.proxy_layers:
                cb, host, port, user, password = layer
                if not host.text() or not port.text().isdigit():
                    continue
                self.proxy_stack.append({
                    'type': cb.currentText().lower(),
                    'host': host.text(),
                    'port': int(port.text()),
                    'user': user.text(),
                    'pass': password.text()
                })

            self.running = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

            local_port = int(self.local_port.text())
            threading.Thread(target=self.run_proxy, args=(local_port,), daemon=True).start()

            self.logs.log("Proxy chain initialized", 'success')
            self.logs.log(f"Active layers: {[p['type'] for p in self.proxy_stack]}", 'debug')

        except Exception as e:
            self.logs.log(f"Initialization failed: {str(e)}", 'error')
            QMessageBox.critical(self, "SYSTEM ERROR", str(e))
    
    def stop_proxy(self):
        self.running = False
        for conn in self.active_connections:
            try: conn.close()
            except: pass
        self.active_connections.clear()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.logs.log("Network termination completed", 'warning')
    
    def run_proxy(self, local_port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('127.0.0.1', local_port))
        server_socket.listen(5)

        self.logs.log(f"Listening on port {local_port}", 'success')
        while self.running:
            try:
                client_socket, addr = server_socket.accept()
                self.active_connections.append(client_socket)
                self.thread_pool.submit(self.handle_client, client_socket)
                self.logs.log(f"Incoming connection from {addr[0]}", 'debug')
            except Exception as e:
                if self.running:
                    self.logs.log(f"Connection error: {str(e)}", 'error')

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
                    # Conecta a um host real para validar
                    sock.connect(('www.google.com', 80))
                    current_socket = sock
                elif proxy['type'] == 'vpn':
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((proxy['host'], proxy['port']))
                    current_socket = sock

            self.redirect_traffic(client_socket, current_socket)

        except Exception as e:
            self.logs.log(f"Connection failure: {str(e)}", 'error')
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
                        self.logs.log(f"Agent spoofed: {self.spoof_counter}", 'spoof')

                    # Sniff
                    if self.inspector.sniff_enabled:
                        self.sniff_history.append(data)
                        self.logs.log(f"Packet: {len(data)}B", 'sniff')
                        self.inspector.log_traffic(data)

                    target = dst if sock is src else src
                    target.sendall(data)
                except:
                    return
    
    def toggle_stealth(self):
        if self.isVisible():
            self.hide()
            self.logs.log("Ghost mode activated", 'warning')
        else:
            self.show()
            self.activateWindow()
            self.logs.log("Returning to visible mode", 'success')
    
    def save_config(self):
        config = []
        for cb, host, port, user, password in self.proxy_layers:
            config.append({
                "type": cb.currentText(),
                "host": host.text(),
                "port": port.text(),
                "user": user.text(),
                "pass": password.text()
            })
        
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "", "JSON Files (*.json)"
        )
        
        if path:
            if not path.endswith('.json'):
                path += '.json'
                
            with open(path, 'w') as f:
                json.dump(config, f)
            self.logs.log("Configuration saved", 'success')
    
    def load_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json)"
        )
        
        if path:
            with open(path, 'r') as f:
                config = json.load(f)
            
            for i, entry in enumerate(config):
                if i < len(self.proxy_layers):
                    cb, host, port, user, password = self.proxy_layers[i]
                    cb.setCurrentText(entry["type"])
                    host.setText(entry["host"])
                    port.setText(str(entry["port"]))
                    user.setText(entry["user"])
                    password.setText(entry["pass"])
            
            self.logs.log("Configuration loaded", 'success')
    
    def start_vpn(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open VPN Configuration", "", "OpenVPN Config (*.ovpn)"
        )
        
        if path:
            try:
                self.vpn_process = subprocess.Popen(['sudo', 'openvpn', '--config', path])
                self.logs.log("VPN process started", 'success')
                if self.hidden_features:
                    self.inspector.sniff_enabled = True
                    self.inspector.spoof_enabled = True
                    self.sniff_btn.setToolTip("Network Sniffer [ON]")
                    self.spoof_btn.setToolTip("Agent Spoofer [ON]")
            except Exception as e:
                self.logs.log(f"Failed to start VPN: {e}", 'error')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Courier New", 9)
    app.setFont(font)
    window = MultiProxyApp()
    window.show()
    sys.exit(app.exec())