# 🛡️ Cyber OSINT Pro Toolkit

### Advanced Open-Source Intelligence & Security Analysis Toolkit

**Cyber OSINT Pro Toolkit** is a modular Python-based OSINT framework designed for **ethical security research, reconnaissance, threat intelligence, and educational cybersecurity analysis**.

It combines asynchronous scanning, IP intelligence, username enumeration, domain analysis, and third-party threat-intelligence APIs into a unified dark-themed interface.

> **Built for security researchers, cybersecurity students, ethical hackers, and OSINT enthusiasts.**

---

## 🚀 Key Features

| Feature                        | Description                                           |
| ------------------------------ | ----------------------------------------------------- |
| ⚡ **Async Scanning**           | High-performance asynchronous OSINT operations        |
| 🌍 **IP Intelligence**         | IP geolocation, network information, and intelligence |
| 🔌 **Port Intelligence**       | Analyze publicly exposed network services             |
| 👤 **Username Enumeration**    | Search usernames across multiple public platforms     |
| 🌐 **Domain Analysis**         | Gather publicly available domain and DNS intelligence |
| 🧠 **Shodan Integration**      | Query internet-connected asset intelligence           |
| 🛡️ **VirusTotal Integration** | Threat and reputation intelligence                    |
| 🎨 **Dark Security UI**        | Modern hacker-style cybersecurity interface           |
| 📊 **Structured Results**      | Organized and readable intelligence output            |
| 🔧 **Modular Architecture**    | Easy to extend with additional OSINT modules          |

---

## 🧩 OSINT Modules

### 🌍 IP Intelligence

Analyze publicly available information associated with an IP address, including:

* Geographic information
* ISP / ASN information
* Network details
* Publicly exposed services
* Security intelligence

### 👤 Username Intelligence

Perform username-based OSINT across multiple publicly accessible platforms.

```text
Username
   ↓
Platform Enumeration
   ↓
Public Profile Discovery
   ↓
Result Aggregation
   ↓
OSINT Report
```

### 🌐 Domain Intelligence

Domain analysis can include publicly available:

* DNS records
* WHOIS information
* IP addresses
* Subdomains
* Network metadata
* Security intelligence

### 🧠 Shodan Intelligence

Optional Shodan integration can provide additional intelligence about publicly indexed internet-facing assets.

### 🛡️ VirusTotal Intelligence

Optional VirusTotal integration can be used for security and reputation analysis of supported indicators.

---

## ⚡ Performance

The toolkit is designed around an **asynchronous architecture** to reduce unnecessary waiting during independent OSINT operations.

```text
                    ┌──────────────────┐
                    │   OSINT Target   │
                    └────────┬─────────┘
                             │
             ┌───────────────┼───────────────┐
             ↓               ↓               ↓
        IP Analysis     Username Scan    Domain Analysis
             │               │               │
             ↓               ↓               ↓
        Intelligence     Platforms       DNS / WHOIS
             │               │               │
             └───────────────┼───────────────┘
                             ↓
                    ┌──────────────────┐
                    │ Results Engine    │
                    └────────┬─────────┘
                             ↓
                    ┌──────────────────┐
                    │ Security Report  │
                    └──────────────────┘
```

---

## 🔑 API Configuration

Create your API credentials according to the providers' documentation and configure them through environment variables or your local configuration file.

Example:

```python
SHODAN_API_KEY = "your_shodan_api_key"
VT_API_KEY = "your_virustotal_api_key"
```

### ⚠️ Security Recommendation

**Never commit API keys to GitHub.**

Use environment variables:

```bash
SHODAN_API_KEY=your_key
VT_API_KEY=your_key
```

Add your secret configuration file to `.gitignore`:

```gitignore
.env
config.py
secrets.json
__pycache__/
*.pyc
```

---

## 🛠️ Technology Stack

* 🐍 **Python**
* ⚡ **AsyncIO**
* 🌐 **Requests / HTTP clients**
* 🔎 **DNS & WHOIS**
* 🧠 **Shodan API**
* 🛡️ **VirusTotal API**
* 🎨 **PyQt5 / Desktop UI**
* 🔐 **Security & OSINT APIs**



## 💻 Installation

Clone the repository:

```bash
git clone https://github.com/CWA-N/cyber-osint-toolkit.git
cd cyber-osint-toolkit
```



## 🎯 Example Use Cases

Cyber OSINT Pro Toolkit can be useful for:

* 🔐 Cybersecurity education
* 🧪 Security research
* 🌐 Asset intelligence
* 🔎 OSINT investigations
* 🛡️ Threat intelligence research
* 👨‍💻 Ethical hacking labs
* 🎓 Cybersecurity projects
* 📚 Practical OSINT learning

---

## 🔒 Responsible Use

This project is intended **only for lawful, authorized, and educational purposes**.

Users are responsible for complying with applicable laws, regulations, platform policies, and authorization requirements.

Do not use this toolkit to:

* Access systems without authorization
* Harass or stalk individuals
* Circumvent authentication or security controls
* Collect private or restricted information
* Conduct unauthorized scanning
* Perform illegal surveillance
* Abuse third-party APIs

**Only investigate assets, accounts, domains, and systems that you own or have explicit permission to analyze.**

---

## 🗺️ Roadmap

* [x] IP intelligence
* [x] Domain analysis
* [x] Username enumeration
* [x] Async scanning architecture
* [x] Shodan integration
* [x] VirusTotal integration
* [x] Dark cybersecurity UI
* [ ] Export reports to JSON
* [ ] Export reports to PDF
* [ ] Advanced result filtering
* [ ] Plugin-based module system
* [ ] Configurable scan profiles
* [ ] Improved logging and error handling
* [ ] Docker support

---

## ⭐ Project Goals

The goal of **Cyber OSINT Pro Toolkit** is to provide a practical, extensible, and beginner-friendly platform for learning how modern OSINT and threat-intelligence workflows can be combined into a single cybersecurity application.

---

## 📜 License

This project is released under the **MIT License** unless otherwise specified.

---

## 👨‍💻 Author

**Cyber OSINT Pro Toolkit**

> Built with Python 🐍 for cybersecurity learning, OSINT research, and ethical security analysis.

### ⭐ If you find this project useful, consider giving the repository a star!
