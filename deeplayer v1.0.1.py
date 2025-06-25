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
import ssl

from collections import deque
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit, QScrollArea,
    QFileDialog, QMessageBox, QFrame, QSizePolicy, QGridLayout
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QTextCursor, QFont, QTextCharFormat, QPalette, QIcon

# Adicionado para AES
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad
import os

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
            'http': self.create_format('#ff8800'),
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
        self.sniff_count = 0
        self.spoof_count = 0
        # Chave fixa para demonstração (em produção, use uma chave segura e armazenada com segurança)
        self.encryption_key = self.derive_key(b'deep-layer-password')
    
    def derive_key(self, password, salt=b'deep-layer-salt', key_length=32):
        return PBKDF2(password, salt, dkLen=key_length)
        
    def should_inspect(self, data):
        return b'HTTP/' in data and b'User-Agent:' in data
    
    def spoof_user_agent(self, data):
        new_agent = random.choice(self.USER_AGENTS)
        self.spoof_count += 1
        return re.sub(
            rb'User-Agent:.*?\r\n',
            f'User-Agent: {new_agent}\r\n'.encode(),
            data,
            count=1
        )
        
    def log_traffic(self, data):
        if self.sniff_enabled and len(data) > 0:
            self.sniff_count += len(data)
            try:
                # Criptografar com AES
                cipher = AES.new(self.encryption_key, AES.MODE_CBC)
                ct_bytes = cipher.encrypt(pad(data, AES.block_size))
                iv = cipher.iv
                with open('.traffic.enc', 'ab') as f:
                    f.write(iv + ct_bytes)
            except Exception as e:
                print(f"Logging error: {e}")

class MultiProxyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DEEP LAYER v1.1.0")
        self.setGeometry(100, 100, 900, 700)
        self.setWindowIcon(QIcon(self.create_icon()))
        
        # Inicializar antes de setup_ui()
        self.status_labels = []  # Lista para os indicadores de status
        
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
        
        self.init_proxy_options()
        
        self.monitor_timer = QTimer(self)
        self.monitor_timer.timeout.connect(self.update_monitor)
        self.monitor_timer.start(1000)
        
        QTimer.singleShot(2000, self.update_proxy_status)
        
    def create_icon(self):
        # Create a simple icon programmatically
        from PyQt6.QtGui import QPixmap, QPainter
        pixmap = QPixmap(32, 32)
        pixmap.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pixmap)
        painter.setBrush(QColor(0, 255, 0))
        painter.setPen(QColor(0, 150, 0))
        painter.drawEllipse(0, 0, 31, 31)
        painter.setPen(QColor(0, 255, 0))
        painter.drawLine(8, 16, 14, 24)
        painter.drawLine(14, 24, 24, 8)
        painter.end()
        return pixmap
        
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
        
        self.connections_label = QLabel("CONNECTIONS: 0")
        self.connections_label.setStyleSheet("color: #00ff00;")
        monitor_layout.addWidget(self.connections_label)
        
        self.traffic_graph = QLabel("[||....................]")
        self.traffic_graph.setStyleSheet("color: #00ff00; font-family: 'Courier New';")
        self.traffic_graph.setAlignment(Qt.AlignmentFlag.AlignRight)
        monitor_layout.addWidget(self.traffic_graph)
        
        main_layout.addWidget(monitor_frame)
        
        # Grupo de camadas de proxy
        proxy_group = QGroupBox(":: PROXY LAYERS ::")
        proxy_layout = QGridLayout(proxy_group)
        proxy_layout.setColumnStretch(0, 1)
        proxy_layout.setColumnStretch(1, 2)
        proxy_layout.setColumnStretch(2, 1)
        proxy_layout.setColumnStretch(3, 1)
        proxy_layout.setColumnStretch(4, 1)
        proxy_layout.setColumnStretch(5, 1)
        
        # Headers
        proxy_layout.addWidget(QLabel("TYPE"), 0, 0)
        proxy_layout.addWidget(QLabel("HOST"), 0, 1)
        proxy_layout.addWidget(QLabel("PORT"), 0, 2)
        proxy_layout.addWidget(QLabel("USER"), 0, 3)
        proxy_layout.addWidget(QLabel("PASS"), 0, 4)
        proxy_layout.addWidget(QLabel("STATUS"), 0, 5)
        
        self.proxy_layers = []
        for i in range(3):
            row = i + 1
            
            cb = QComboBox()
            cb.addItems(["SOCKS5", "Tor", "VPN", "HTTP", "HTTPS"])
            cb.setFixedWidth(100)
            proxy_layout.addWidget(cb, row, 0)
            
            host = QLineEdit()
            proxy_layout.addWidget(host, row, 1)
            
            port = QLineEdit()
            port.setFixedWidth(60)
            proxy_layout.addWidget(port, row, 2)
            
            user = QLineEdit()
            user.setFixedWidth(80)
            proxy_layout.addWidget(user, row, 3)
            
            password = QLineEdit()
            password.setEchoMode(QLineEdit.EchoMode.Password)
            password.setFixedWidth(80)
            proxy_layout.addWidget(password, row, 4)
            
            status = QLabel("❓")
            status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            proxy_layout.addWidget(status, row, 5)
            self.status_labels.append(status)
            
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
        
        self.test_btn = QPushButton("Test All Proxies")
        self.test_btn.clicked.connect(self.update_proxy_status)
        local_layout.addWidget(self.test_btn)
        
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
        main_layout.addWidget(self.logs, 1)
        
        self.installEventFilter(self)
        self.logs.log("Deep Layer Proxy initialized", 'success')
        self.logs.log("Press Ctrl+G for Ghost Mode, Ctrl+Alt+U for Advanced Features", 'info')
    
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
        # Configuração mais segura - campos vazios por padrão
        for i, layer in enumerate(self.proxy_layers):
            cb, host, port, user, password = layer
            cb.setCurrentIndex(0)  # Define como SOCKS5
            
            # Limpa os campos
            host.clear()
            port.clear()
            user.clear()
            password.clear()
            
            # Define status inicial
            self.status_labels[i].setText("⚪")
            self.status_labels[i].setToolTip("Not configured")
    
    def update_monitor(self):
        self.spoof_label.setText(f"SPOOF: {self.inspector.spoof_count}")
        total_kb = self.inspector.sniff_count // 1024
        self.sniff_label.setText(f"SNIFF: {total_kb}KB")
        self.connections_label.setText(f"CONNECTIONS: {len(self.active_connections)}")
        
        # Update traffic graph
        if self.sniff_history:
            traffic_level = min(len(self.sniff_history), 20)
            self.traffic_graph.setText(f"[{'|'*traffic_level}{'.'*(20-traffic_level)}]")
        
        # Periodically test proxies
        if time.time() % 10 < 1:  # Test every 10 seconds
            self.update_proxy_status()
    
    def toggle_advanced_mode(self):
        self.hidden_features = not self.hidden_features
        self.sniff_btn.setEnabled(self.hidden_features)
        self.spoof_btn.setEnabled(self.hidden_features)
        status = "UNLOCKED" if self.hidden_features else "DISABLED"
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
    
    def update_proxy_status(self):
        for i, layer in enumerate(self.proxy_layers):
            cb, host, port, user, password = layer
            proxy_type = cb.currentText().lower()
            proxy_host = host.text()
            proxy_port = port.text()
            
            # Verificar se o proxy está configurado
            if not proxy_host or not proxy_port or not proxy_port.isdigit():
                self.status_labels[i].setText("⚪")
                self.status_labels[i].setToolTip("Not configured")
                continue  # Pular teste para proxies não configurados
            
            # Construir configuração do proxy
            proxy_config = {
                'type': proxy_type,
                'host': proxy_host,
                'port': int(proxy_port),
                'user': user.text(),
                'pass': password.text()
            }
            
            # Testar o proxy
            if self.test_proxy(proxy_config):
                self.status_labels[i].setText("🟢")
                self.status_labels[i].setToolTip("Online")
            else:
                self.status_labels[i].setText("🔴")
                self.status_labels[i].setToolTip("Offline")
    
    def test_proxy(self, proxy):
        try:
            sock = socks.socksocket()
            
            # Map proxy type
            if proxy['type'] == 'tor':
                proxy_type = socks.SOCKS5
            elif proxy['type'] == 'http':
                proxy_type = socks.HTTP
            elif proxy['type'] == 'https':
                proxy_type = socks.HTTP
            else:  # SOCKS5 by default
                proxy_type = socks.SOCKS5
                
            # Configure proxy
            if proxy['user'] and proxy['pass']:
                sock.set_proxy(
                    proxy_type,
                    proxy['host'],
                    proxy['port'],
                    username=proxy['user'],
                    password=proxy['pass']
                )
            else:
                sock.set_proxy(
                    proxy_type,
                    proxy['host'],
                    proxy['port']
                )
            
            # Set timeout and test connection
            sock.settimeout(5)
            sock.connect(('www.example.com', 80))
            sock.close()
            return True
        except Exception as e:
            print(f"Proxy test failed: {e}")
            return False
    
    def start_proxy(self):
        try:
            self.proxy_stack = []
            for layer in self.proxy_layers:
                cb, host, port, user, password = layer
                if not host.text() or not port.text().isdigit():
                    continue
                    
                proxy_type = cb.currentText().lower()
                if proxy_type == 'https':
                    # HTTPS proxies need special handling
                    proxy_type = 'http'
                    
                self.proxy_stack.append({
                    'type': proxy_type,
                    'host': host.text(),
                    'port': int(port.text()),
                    'user': user.text(),
                    'pass': password.text()
                })

            if not self.proxy_stack:
                self.logs.log("No valid proxies configured", 'error')
                return

            self.running = True
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

            local_port = int(self.local_port.text())
            threading.Thread(target=self.run_proxy, args=(local_port,), daemon=True).start()

            self.logs.log("Proxy chain initialized", 'success')
            self.logs.log(f"Active layers: {[p['type'] for p in self.proxy_stack]}", 'debug')
            self.update_proxy_status()

        except Exception as e:
            self.logs.log(f"Initialization failed: {str(e)}", 'error')
            QMessageBox.critical(self, "SYSTEM ERROR", str(e))
    
    def stop_proxy(self):
        self.running = False
        self.logs.log("Terminating network connections...", 'warning')
        
        # Close all active connections
        for conn in self.active_connections[:]:
            try:
                conn.close()
            except:
                pass
            if conn in self.active_connections:
                self.active_connections.remove(conn)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=False, cancel_futures=True)
        self.thread_pool = ThreadPoolExecutor(max_workers=50)
        
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
            # Read the first data to determine the target
            data = client_socket.recv(4096)
            if not data:
                return
                
            # Parse target from CONNECT request
            if data.startswith(b'CONNECT'):
                # HTTPS proxy request
                host_port = data.split(b' ')[1].split(b':')
                target_host = host_port[0].decode()
                target_port = int(host_port[1])
                self.logs.log(f"HTTPS request to {target_host}:{target_port}", 'http')
                
                # Acknowledge CONNECT
                client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            else:
                # HTTP request
                try:
                    host_line = next(line for line in data.split(b'\r\n') if line.startswith(b'Host:'))
                    host_port = host_line.split(b':')[1].strip().split(b':')
                    target_host = host_port[0].decode()
                    target_port = int(host_port[1]) if len(host_port) > 1 else 80
                    self.logs.log(f"HTTP request to {target_host}:{target_port}", 'http')
                except:
                    self.logs.log("Could not parse target from request", 'error')
                    return

            # Get the first active proxy
            if not self.proxy_stack:
                self.logs.log("No proxies available for connection", 'error')
                return
                
            proxy = self.proxy_stack[0]  # Use the first configured proxy
            
            # Create proxy socket
            sock = socks.socksocket()
            
            # Map proxy type
            if proxy['type'] == 'tor':
                proxy_type = socks.SOCKS5
            elif proxy['type'] == 'http':
                proxy_type = socks.HTTP
            else:  # SOCKS5 by default
                proxy_type = socks.SOCKS5
                
            # Configure proxy
            if proxy['user'] and proxy['pass']:
                sock.set_proxy(
                    proxy_type,
                    proxy['host'],
                    proxy['port'],
                    True,
                    proxy['user'],
                    proxy['pass']
                )
            else:
                sock.set_proxy(
                    proxy_type,
                    proxy['host'],
                    proxy['port']
                )
                
            # Connect to target through proxy
            sock.connect((target_host, target_port))
            
            # If HTTPS, we've already acknowledged the CONNECT, just forward data
            # For HTTP, send the initial data we received
            if not data.startswith(b'CONNECT'):
                sock.sendall(data)
                
            # Start forwarding traffic
            self.redirect_traffic(client_socket, sock)

        except Exception as e:
            self.logs.log(f"Connection failure: {str(e)}", 'error')
        finally:
            try:
                client_socket.close()
            except:
                pass
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

                    # Store for traffic visualization
                    self.sniff_history.append(data)
                    
                    # Spoof
                    if self.inspector.spoof_enabled and self.inspector.should_inspect(data):
                        data = self.inspector.spoof_user_agent(data)
                        self.logs.log(f"Agent spoofed: {self.inspector.spoof_count}", 'spoof')

                    # Sniff
                    if self.inspector.sniff_enabled:
                        self.inspector.log_traffic(data)
                        self.logs.log(f"Packet captured: {len(data)}B", 'sniff')

                    # Send data to the other side
                    target = dst if sock is src else src
                    target.sendall(data)
                except Exception as e:
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
                json.dump(config, f, indent=2)
            self.logs.log("Configuration saved", 'success')
    
    def load_config(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", "JSON Files (*.json)"
        )
        
        if path:
            try:
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
                self.update_proxy_status()
            except Exception as e:
                self.logs.log(f"Failed to load config: {str(e)}", 'error')
    
    def start_vpn(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open VPN Configuration", "", "OpenVPN Config (*.ovpn)"
        )
        
        if path:
            try:
                # Platform-specific VPN startup
                if sys.platform == 'win32':
                    self.vpn_process = subprocess.Popen(['openvpn-gui', '--connect', path])
                else:
                    self.vpn_process = subprocess.Popen(['openvpn', '--config', path])
                
                self.logs.log("VPN process started", 'success')
                
                # Enable advanced features if in hidden mode
                if self.hidden_features:
                    self.inspector.sniff_enabled = True
                    self.inspector.spoof_enabled = True
                    self.sniff_btn.setToolTip("Network Sniffer [ON]")
                    self.spoof_btn.setToolTip("Agent Spoofer [ON]")
                    self.logs.log("Advanced features activated with VPN", 'success')
            except Exception as e:
                self.logs.log(f"Failed to start VPN: {e}", 'error')

if __name__ == "__main__":
    app = QApplication(sys.argv)
    font = QFont("Courier New", 9)
    app.setFont(font)
    window = MultiProxyApp()
    window.show()
    sys.exit(app.exec())
