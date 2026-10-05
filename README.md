# 🛡️ CyberShield AI

**Smart Digital Safety System** — Detect phishing links, suspicious messages, and weak passwords before they harm you.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Django](https://img.shields.io/badge/Django-6.x-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## 📖 About

**CyberShield AI** is an innovative cybersecurity project designed to protect individuals and businesses from modern digital threats. The system analyzes suspicious URLs and messages, evaluates password strength, and provides security alerts with practical recommendations.

Its main objective is to reduce the risk of phishing, online fraud, and unsafe digital practices through early warnings and awareness.

The proposed solution is developed as a web application and can be expanded into a mobile app or browser extension in the future.

---

## ✨ Features

- 🔍 **URL Scanner** — Detects phishing and malicious links using pattern analysis, TLD reputation, and SSL verification
- 💬 **Message Scanner** — Analyzes SMS and email text for urgency, fraud phrases, and sensitive-info requests
- 🔑 **Password Checker** — Grades password strength and gives actionable improvement tips
- 📊 **Scan History** — Stores all past scans for review
- 🎨 **Modern UI** — Responsive dark-themed interface with animations

---

## 🛠️ Tech Stack

| Layer | Technologies |
|-------|--------------|
| **Backend** | Python 3, Django 6 |
| **Frontend** | HTML5, CSS3, JavaScript (vanilla) |
| **Database** | SQLite (dev) |
| **Security** | SSL inspection, rule-based heuristics |

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/24kq1a6178-commits/cybershield-ai.git
cd cybershield-ai

# 2. Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create a .env file (see .env.example)
# Set DJANGO_SECRET_KEY, DEBUG, ALLOWED_HOSTS

# 5. Apply migrations
python manage.py migrate

# 6. Create an admin user (optional)
python manage.py createsuperuser

# 7. Run the development server
python manage.py runserver
```
