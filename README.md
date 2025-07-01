# SubSL - Subdomain Scanner with Live Dashboard

SubSL is a powerful subdomain enumeration and monitoring tool featuring a live web dashboard for tracking scan progress in real-time.

## ✨ Features
- OSINT-based subdomain enumeration (e.g. crt.sh, AlienVault, HackerTarget)
- Bruteforce subdomain discovery
- Real-time DNS resolution & HTTP reachability checks
- Web dashboard with live stats and logs via WebSocket
- Optional Shodan integration for more insights

## 📦 Requirements
- Python 3.9+
- Linux recommended (Debian, Kali, Arch tested)

## 🔧 Installation
```bash
git clone https://github.com/YOUR_USERNAME/subsl.git
cd subsl
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🔑 Environment Variables (.env)
Create a `.env` file in the root directory:

```env
SHODAN_API_KEY=your_shodan_api_key
GITHUB_TOKEN=your_github_token
SECURITYTRAILS_API_KEY=your_securitytrails_key
```

## 🚀 Usage
### Basic Scan:
```bash
python3 subSL.py example.com
```

### With Web Dashboard:
```bash
python3 subSL.py example.com --web
```

Open [http://localhost:8000](http://localhost:8000) in your browser to monitor.

## 🛠️ Options
- `--web` : Enable web dashboard
- `--no-brute` : Disable bruteforce subdomain guessing
- `--wordlist PATH` : Custom wordlist for bruteforce

## 🧠 Notes
- Port 8000 must be free.
- If WebSocket live updates don’t work, install proper backends:
  ```bash
  pip install 'uvicorn[standard]'
  ```

## 📄 License
MIT © 2025 sb3ly
