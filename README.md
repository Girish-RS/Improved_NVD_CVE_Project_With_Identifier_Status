# 🧠 NVD CVE Dashboard — Flask + SQLite + NVD API

![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)
![Flask](https://img.shields.io/badge/Flask-Framework-lightgrey)
![Database](https://img.shields.io/badge/Database-SQLite-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Project-Active-brightgreen)

A full-stack web application that consumes, stores, and visualizes real-time CVE (Common Vulnerabilities and Exposures) data from the **[National Vulnerability Database (NVD)](https://nvd.nist.gov/)** API.

Built using **Flask**, **SQLite**, and **JavaScript**, this project allows users to synchronize, filter, and explore CVE data interactively through a clean and responsive UI.

---

## 🚀 Features

✅ Fetch CVE information from the official NVD API  
✅ Store vulnerabilities locally in an **SQLite database**  
✅ Batch & incremental synchronization support  
✅ Clean, sortable, paginated **CVE List UI**  
✅ Clickable rows open a detailed CVE info page  
✅ Includes:
- CVE ID  
- Source Identifier  
- Published & Last Modified dates  
- CVSS v2 metrics (score, severity, vector string)  
- CPE configurations (criteria, match ID, vulnerability)  
✅ REST APIs for CVE filtering and details  
✅ Unit-test-ready & easily extendable

---

## 🧩 Tech Stack

| Layer | Technology |
|--------|-------------|
| **Frontend** | HTML5, CSS3, JavaScript |
| **Backend** | Python (Flask) |
| **Database** | SQLite (via SQLAlchemy ORM) |
| **API Source** | [NVD REST API v2.0](https://services.nvd.nist.gov/rest/json/cves/2.0) |

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-username>/nvd-cve-flask-project.git
cd nvd-cve-flask-project
