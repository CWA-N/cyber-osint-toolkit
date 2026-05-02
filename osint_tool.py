import sys
import re
import requests
import socket
import whois
import dns.resolver
import phonenumbers
from phonenumbers import geocoder, timezone, carrier
from ipwhois import IPWhois
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget, 
                            QLineEdit, QPushButton, QTextEdit, QLabel, QGroupBox, QFormLayout, 
                            QSplitter, QMessageBox, QFileDialog, QProgressBar)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor

class OSINTWorker(QThread):
    result_ready = pyqtSignal(str, str)
    progress_update = pyqtSignal(int)
    finished = pyqtSignal()

    def __init__(self, target_type, target_value):
        super().__init__()
        self.target_type = target_type
        self.target_value = target_value
        self.running = True

    def run(self):
        try:
            self.progress_update.emit(10)
            
            if self.target_type == "email":
                result = self.email_osint(self.target_value)
            elif self.target_type == "username":
                result = self.username_osint(self.target_value)
            elif self.target_type == "domain":
                result = self.domain_osint(self.target_value)
            elif self.target_type == "phone":
                result = self.phone_osint(self.target_value)
            elif self.target_type == "ip":
                result = self.ip_osint(self.target_value)
            else:
                result = "Invalid target type"
            
            self.progress_update.emit(90)
            self.result_ready.emit(self.target_type, result)
        except Exception as e:
            self.result_ready.emit(self.target_type, f"Error: {str(e)}")
        finally:
            self.progress_update.emit(100)
            self.finished.emit()

    def stop(self):
        self.running = False

    def email_osint(self, email):
        result = f"📧 Email Investigation: {email}\n{'='*50}\n"
        
        # Email validation
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return result + "❌ Invalid email format"
        
        domain = email.split('@')[1]
        result += f"🔍 Domain: {domain}\n\n"
        
        # Breach check
        result += "🔒 Checking breach history...\n"
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {'User-Agent': 'OSINT-Tool'}
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                breaches = response.json()
                result += f"⚠️ Account found in {len(breaches)} breaches:\n"
                for breach in breaches:
                    result += f"  - {breach['Name']} ({breach['BreachDate']})\n"
            else:
                result += "✅ No breaches found\n"
        except Exception as e:
            result += f"❌ Breach check error: {str(e)}\n"
        
        # Domain information
        result += "\n🌐 Domain investigation:\n"
        try:
            domain_info = whois.whois(domain)
            result += f"  Registrar: {domain_info.registrar}\n"
            result += f"  Creation Date: {domain_info.creation_date}\n"
            result += f"  Expiration Date: {domain_info.expiration_date}\n"
            result += f"  Name Servers: {', '.join(domain_info.name_servers[:3])}...\n"
        except Exception as e:
            result += f"❌ Domain lookup error: {str(e)}\n"
        
        return result

    def username_osint(self, username):
        result = f"👤 Username Investigation: {username}\n{'='*50}\n\n"
        
        sites = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "Facebook": f"https://facebook.com/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "Twitch": f"https://twitch.tv/{username}"
        }
        
        result += "🔍 Checking social media presence:\n\n"
        for platform, url in sites.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    result += f"✅ {platform}: FOUND\n  🔗 {url}\n"
                else:
                    result += f"❌ {platform}: Not found\n"
            except:
                result += f"⚠️ {platform}: Check failed\n"
        
        return result

    def domain_osint(self, domain):
        result = f"🌐 Domain Investigation: {domain}\n{'='*50}\n\n"
        
        # WHOIS lookup
        try:
            result += "📋 WHOIS Information:\n"
            domain_info = whois.whois(domain)
            result += f"  Registrar: {domain_info.registrar}\n"
            result += f"  Creation Date: {domain_info.creation_date}\n"
            result += f"  Expiration Date: {domain_info.expiration_date}\n"
            result += f"  Name Servers: {', '.join(domain_info.name_servers[:3])}...\n\n"
        except Exception as e:
            result += f"❌ WHOIS lookup error: {str(e)}\n\n"
        
        # DNS records
        result += "🔗 DNS Records:\n"
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                result += f"  {rtype} Records:\n"
                for rdata in answers:
                    result += f"    - {rdata.to_text()}\n"
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                continue
            except Exception as e:
                result += f"  ❌ DNS lookup error for {rtype}: {str(e)}\n"
        
        # Subdomain discovery
        result += "\n🔍 Common Subdomains:\n"
        subdomains = ['mail', 'webmail', 'ftp', 'blog', 'admin', 'portal', 'www', 'web', 'app', 'api']
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                result += f"  ✅ Found: {fqdn}\n"
            except:
                continue
        
        return result

    def phone_osint(self, phone_number):
        result = f"📱 Phone Investigation: {phone_number}\n{'='*50}\n\n"
        
        try:
            # Format validation
            parsed = phonenumbers.parse(phone_number, None)
            if not phonenumbers.is_valid_number(parsed):
                return result + "❌ Invalid phone number"
            
            # Basic info
            formatted = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
            region = phonenumbers.region_code_for_number(parsed)
            country = phonenumbers.region_name_for_number(parsed)
            
            result += "📋 Basic Information:\n"
            result += f"  Formatted: {formatted}\n"
            result += f"  Region Code: {region}\n"
            result += f"  Country: {country}\n"
            
            # Location
            location = geocoder.description_for_number(parsed, "en")
            if location:
                result += f"  Location: {location}\n"
            
            # Timezone
            time_zones = timezone.time_zones_for_number(parsed)
            if time_zones:
                result += f"  Time Zones: {', '.join(time_zones)}\n"
            
            # Carrier
            try:
                service_provider = carrier.name_for_number(parsed, "en")
                if service_provider:
                    result += f"  Carrier: {service_provider}\n"
            except:
                pass
            
            # Number type
            number_type = phonenumbers.number_type(parsed)
            type_map = {
                phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line",
                phonenumbers.PhoneNumberType.MOBILE: "Mobile",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Toll-Free",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
                phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
                phonenumbers.PhoneNumberType.VOIP: "VoIP",
                phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
                phonenumbers.PhoneNumberType.PAGER: "Pager",
                phonenumbers.PhoneNumberType.UAN: "Universal Access Number",
                phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
                phonenumbers.PhoneNumberType.UNKNOWN: "Unknown"
            }
            readable_type = type_map.get(number_type, "Unknown")
            result += f"  Type: {readable_type}\n"
            
            # Validation flags
            result += f"  Valid: {'Yes' if phonenumbers.is_valid_number(parsed) else 'No'}\n"
            result += f"  Possible: {'Yes' if phonenumbers.is_possible_number(parsed) else 'No'}\n"
            
        except phonenumbers.phonenumberutil.NumberParseException:
            return result + "❌ Invalid phone number format"
        
        return result

    def ip_osint(self, ip_address):
        result = f"🌍 IP Investigation: {ip_address}\n{'='*50}\n\n"
        
        # Geolocation
        try:
            response = requests.get(f"http://ip-api.com/json/{ip_address}")
            data = response.json()
            if data['status'] == 'success':
                result += "📍 Geolocation:\n"
                result += f"  Country: {data['country']}\n"
                result += f"  Region: {data['regionName']}\n"
                result += f"  City: {data['city']}\n"
                result += f"  ZIP: {data['zip']}\n"
                result += f"  ISP: {data['isp']}\n"
                result += f"  Organization: {data['org']}\n\n"
        except Exception as e:
            result += f"❌ Geolocation error: {str(e)}\n\n"
        
        # WHOIS lookup
        try:
            result += "📋 WHOIS Information:\n"
            obj = IPWhois(ip_address)
            results = obj.lookup_rdap()
            result += f"  ASN: {results.get('asn')}\n"
            result += f"  ASN Description: {results.get('asn_description')}\n"
            result += f"  Network: {results.get('network')}\n"
        except Exception as e:
            result += f"❌ WHOIS lookup error: {str(e)}\n"
        
        return result

class OSINTTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("OSINT Toolkit")
        self.setGeometry(100, 100, 900, 700)
        
        # Set dark theme
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2D2D30;
            }
            QWidget {
                background-color: #2D2D30;
                color: #DCDCDC;
            }
            QLineEdit {
                background-color: #3C3C40;
                color: #FFFFFF;
                border: 1px solid #555555;
                border-radius: 4px;
                padding: 5px;
            }
            QPushButton {
                background-color: #007ACC;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1C97EA;
            }
            QPushButton:pressed {
                background-color: #0062A3;
            }
            QTextEdit {
                background-color: #1E1E1E;
                color: #DCDCDC;
                border: 1px solid #555555;
                border-radius: 4px;
                font-family: Consolas, monospace;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background: #2D2D30;
            }
            QTabBar::tab {
                background: #2D2D30;
                color: #DCDCDC;
                padding: 8px 20px;
                border: 1px solid #555555;
                border-bottom: none;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #007ACC;
                color: white;
            }
            QGroupBox {
                border: 1px solid #555555;
                border-radius: 4px;
                margin-top: 1ex;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 5px;
            }
            QLabel {
                color: #DCDCDC;
            }
            QProgressBar {
                border: 1px solid #555555;
                border-radius: 4px;
                text-align: center;
                background: #3C3C40;
            }
            QProgressBar::chunk {
                background: #007ACC;
            }
        """)
        
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Title
        title_label = QLabel("OSINT INVESTIGATION TOOL")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet("color: #4FC3F7; margin-bottom: 20px;")
        main_layout.addWidget(title_label)
        
        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Create tab for each OSINT type
        self.create_email_tab()
        self.create_username_tab()
        self.create_domain_tab()
        self.create_phone_tab()
        self.create_ip_tab()
        
        # Results area
        results_group = QGroupBox("Investigation Results")
        results_layout = QVBoxLayout()
        
        # Add copy button
        buttons_layout = QHBoxLayout()
        self.copy_button = QPushButton("Copy Results")
        self.copy_button.clicked.connect(self.copy_results)
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        buttons_layout.addWidget(self.copy_button)
        buttons_layout.addWidget(self.clear_button)
        results_layout.addLayout(buttons_layout)
        
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.results_text.setFont(QFont("Consolas", 10))
        
        results_layout.addWidget(self.results_text)
        results_group.setLayout(results_layout)
        main_layout.addWidget(results_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        
        # Initialize worker
        self.worker = None

    def copy_results(self):
        """Copy results to clipboard"""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.results_text.toPlainText())
        self.status_bar.showMessage("Results copied to clipboard!")

    def clear_results(self):
        """Clear results area"""
        self.results_text.clear()
        self.status_bar.showMessage("Results cleared")

    def create_email_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input area
        input_group = QGroupBox("Email Investigation")
        input_layout = QFormLayout()
        
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Enter email address (e.g., user@example.com)")
        input_layout.addRow(QLabel("Email Address:"), self.email_input)
        
        email_btn = QPushButton("Investigate Email")
        email_btn.clicked.connect(lambda: self.start_investigation("email", self.email_input.text()))
        input_layout.addRow(email_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Tips
        tips_group = QGroupBox("Email OSINT Tips")
        tips_layout = QVBoxLayout()
        
        tips_text = QLabel(
            "• Check for data breaches using HaveIBeenPwned\n"
            "• Identify the domain registrar and registration dates\n"
            "• Verify email format and domain existence\n"
            "• Search for related accounts using the email address"
        )
        tips_text.setFont(QFont("Arial", 9))
        tips_layout.addWidget(tips_text)
        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📧 Email")

    def create_username_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input area
        input_group = QGroupBox("Username Investigation")
        input_layout = QFormLayout()
        
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Enter username (e.g., johndoe)")
        input_layout.addRow(QLabel("Username:"), self.username_input)
        
        username_btn = QPushButton("Investigate Username")
        username_btn.clicked.connect(lambda: self.start_investigation("username", self.username_input.text()))
        input_layout.addRow(username_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Tips
        tips_group = QGroupBox("Username OSINT Tips")
        tips_layout = QVBoxLayout()
        
        tips_text = QLabel(
            "• Search across multiple social media platforms\n"
            "• Look for consistent profile pictures or bios\n"
            "• Check for account creation dates\n"
            "• Identify patterns in usernames across platforms"
        )
        tips_text.setFont(QFont("Arial", 9))
        tips_layout.addWidget(tips_text)
        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "👤 Username")

    def create_domain_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input area
        input_group = QGroupBox("Domain Investigation")
        input_layout = QFormLayout()
        
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter domain (e.g., example.com)")
        input_layout.addRow(QLabel("Domain:"), self.domain_input)
        
        domain_btn = QPushButton("Investigate Domain")
        domain_btn.clicked.connect(lambda: self.start_investigation("domain", self.domain_input.text()))
        input_layout.addRow(domain_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Tips
        tips_group = QGroupBox("Domain OSINT Tips")
        tips_layout = QVBoxLayout()
        
        tips_text = QLabel(
            "• Check WHOIS information for domain registration\n"
            "• Look for DNS records (A, MX, TXT, etc.)\n"
            "• Discover common subdomains\n"
            "• Check historical DNS records using specialized services"
        )
        tips_text.setFont(QFont("Arial", 9))
        tips_layout.addWidget(tips_text)
        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🌐 Domain")

    def create_phone_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input area
        input_group = QGroupBox("Phone Number Investigation")
        input_layout = QFormLayout()
        
        self.phone_input = QLineEdit()
        self.phone_input.setPlaceholderText("Enter phone number (e.g., +15551234567)")
        input_layout.addRow(QLabel("Phone Number:"), self.phone_input)
        
        # Buttons layout
        buttons_layout = QHBoxLayout()
        phone_btn = QPushButton("Investigate Phone Number")
        phone_btn.clicked.connect(lambda: self.start_investigation("phone", self.phone_input.text()))
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear_phone_input)
        
        buttons_layout.addWidget(phone_btn)
        buttons_layout.addWidget(clear_btn)
        input_layout.addRow(buttons_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Tips
        tips_group = QGroupBox("Phone OSINT Tips")
        tips_layout = QVBoxLayout()
        
        tips_text = QLabel(
            "• Validate phone number format and country code\n"
            "• Identify carrier and location information\n"
            "• Search for associated social media accounts\n"
            "• Check for number reputation using specialized services"
        )
        tips_text.setFont(QFont("Arial", 9))
        tips_layout.addWidget(tips_text)
        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "📱 Phone")
    
    def clear_phone_input(self):
        """Clear the phone input field"""
        self.phone_input.clear()
        self.status_bar.showMessage("Phone input cleared")

    def create_ip_tab(self):
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Input area
        input_group = QGroupBox("IP Address Investigation")
        input_layout = QFormLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP address (e.g., 8.8.8.8)")
        input_layout.addRow(QLabel("IP Address:"), self.ip_input)
        
        ip_btn = QPushButton("Investigate IP Address")
        ip_btn.clicked.connect(lambda: self.start_investigation("ip", self.ip_input.text()))
        input_layout.addRow(ip_btn)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Tips
        tips_group = QGroupBox("IP OSINT Tips")
        tips_layout = QVBoxLayout()
        
        tips_text = QLabel(
            "• Geolocate the IP address\n"
            "• Identify the ISP and organization\n"
            "• Check for known malicious activity\n"
            "• Look up ASN and network information"
        )
        tips_text.setFont(QFont("Arial", 9))
        tips_layout.addWidget(tips_text)
        tips_group.setLayout(tips_layout)
        layout.addWidget(tips_group)
        
        tab.setLayout(layout)
        self.tabs.addTab(tab, "🌍 IP Address")

    def start_investigation(self, target_type, target_value):
        if not target_value:
            QMessageBox.warning(self, "Input Error", "Please enter a value to investigate")
            return
        
        # Clear previous results
        self.results_text.clear()
        
        # Show initial message
        self.results_text.append(f"Starting {target_type} investigation for: {target_value}")
        self.results_text.append("Gathering information...")
        self.results_text.append("-" * 50)
        
        # Disable UI during investigation
        self.set_ui_enabled(False)
        
        # Start worker thread
        self.worker = OSINTWorker(target_type, target_value)
        self.worker.result_ready.connect(self.display_result)
        self.worker.progress_update.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_investigation_complete)
        self.worker.start()
        
        self.status_bar.showMessage(f"Investigating {target_type}: {target_value}...")

    def display_result(self, target_type, result):
        self.results_text.append(result)
        self.results_text.append("\n" + "=" * 50)
        self.results_text.append("Investigation complete.")

    def on_investigation_complete(self):
        self.set_ui_enabled(True)
        self.status_bar.showMessage("Investigation completed successfully")
        self.progress_bar.setValue(0)

    def set_ui_enabled(self, enabled):
        self.email_input.setEnabled(enabled)
        self.username_input.setEnabled(enabled)
        self.domain_input.setEnabled(enabled)
        self.phone_input.setEnabled(enabled)
        self.ip_input.setEnabled(enabled)
        self.tabs.setEnabled(enabled)
        self.copy_button.setEnabled(enabled)
        self.clear_button.setEnabled(enabled)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Set dark palette
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(45, 45, 48))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(30, 30, 30))
    palette.setColor(QPalette.AlternateBase, QColor(45, 45, 48))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(45, 45, 48))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Highlight, QColor(0, 122, 204))
    palette.setColor(QPalette.HighlightedText, Qt.white)
    app.setPalette(palette)
    
    window = OSINTTool()
    window.show()
    sys.exit(app.exec_())
