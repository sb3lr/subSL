
# SubSL: أداة متقدمة لاكتشاف وتحليل النطاقات الفرعية

![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
[![GitHub followers](https://img.shields.io/github/followers/sb3ly?style=social)](https://github.com/sb3ly)

---

SubSL is a powerful subdomain enumeration and analysis tool designed for red teamers, bug bounty hunters, and cybersecurity researchers. It combines OSINT gathering, DNS brute-forcing, HTTP probing, and a built-in live dashboard to provide real-time visibility into discovered subdomains.

## Features

- 🔍 OSINT Subdomain Gathering (SecurityTrails, Shodan, GitHub)
- 🔎 Brute-force DNS Enumeration
- 🌐 HTTP Probing and Validation
- 📊 Real-time Web Dashboard (`--web`)
- 🛡️ Subdomain Takeover Detection
- 📝 Export results to TXT or JSON

## Installation

```bash
git clone https://github.com/sb3ly/SubSL.git
cd SubSL
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Basic scan with OSINT + brute force + HTTP check
python3 subSL.py example.com

# Enable web dashboard on localhost:8000
python3 subSL.py example.com --web
```

## API Keys Setup

Create a `.env` file in the root directory with the following:

```
SECURITYTRAILS_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
GITHUB_TOKEN=your_key_here
```

## License

This project is licensed under the MIT License.

---

<div dir="rtl" align="center">

## 🇸🇦 وصف الأداة بالعربية

SubSL هي أداة متقدمة لاكتشاف النطاقات الفرعية، موجهة للهاكر الأخلاقيين والباحثين في الأمن السيبراني. توفر لك تحليلاً شاملاً عن طريق:

- جمع النطاقات الفرعية من مصادر OSINT
- التخمين باستخدام wordlist لاكتشاف نطاقات مخفية
- فحص DNS وHTTP
- واجهة ويب تفاعلية تعرض التحديثات بشكل مباشر
- كشف احتمالية الاستيلاء على النطاقات الفرعية
- تصدير النتائج إلى ملفات

</div>
