# SQLMaster: Advanced SQL Injection Scanner & Exploitation Tool

<div align="center">

![SQLMaster Banner](https://img.shields.io/badge/SQLMaster-Advanced%20SQLi%20Tool-red)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)

**The silent predator that sniffs out SQL vulnerabilities before they can scream**

</div>

##  Quick Start

### Installation
```bash
# Clone 
git clone https://github.com/ekomsSavior/SQLmaster.git
cd SQLmaster

# install dependencies
pip3 install -r requirements.txt
```

### Execution

```bash
sudo python3 main.py
```

SQLMaster is a **hunter-killer platform** designed to find, exploit, and dominate SQL injection vulnerabilities with surgical precision. Built for penetration testers and security researchers.


## Features

###  **Advanced Detection**
- **Error-Based SQLi**: Catch database servers when they spill their secrets
- **Union-Based SQLi**: Force databases to reveal their structure at gunpoint
- **Boolean/Time-Based Blind SQLi**: Extract data when databases play hard to get
- **Stacked Queries**: Execute multiple commands and own the database session
- **Out-of-Band Exfiltration**: Data extraction even when traditional methods fail

###  **Evasion Capabilities**
- **SPA Detection**: Identifies Single Page Applications to avoid false positives
- **WAF Bypass**: Multiple payload variations to slip past security filters
- **Rate Limit Evasion**: Intelligent timing and randomization to avoid detection

###  **Exploitation Arsenal**
- **Database Enumeration**: Map the entire database landscape
- **Table/Column Discovery**: Find exactly where the valuable data hides
- **Data Extraction**: Pull credentials, PII, and everything valuable
- **Out-of-Band Channels**: DNS/HTTP exfiltration for tough target


### Operational Workflow:
1. **Target Acquisition**: Point SQLMaster at your target
2. **Reconnaissance**: Let it fingerprint technologies and detect WAFs
3. **Vulnerability Hunting**: Watch as it systematically tests every parameter
4. **Exploitation**: Choose your attack vector from discovered vulnerabilities
5. **Data Extraction**: Pull the database contents to your local machine
6. **Persistence**: Save results for your penetration test report


##  Output: Intel

SQLMaster doesn't just tell you there's a vulnerability - it shows you:

- **Detailed vulnerability information** with confidence ratings
- **Extracted database schemas** and table structures
- **Actual data dumps** with column mappings
- **Timing information** for blind SQL injection
- **Full exploitation paths** with step-by-step guidance

###  **LEGAL WARNING**
SQLMaster is developed for:
- **Authorized penetration testing** with explicit written permission
- **Security research** on systems you own or have permission to test
- **Educational purposes** in controlled, isolated environments

**The developer assumes NO liability for misuse of this tool.**

##  For the Curious Minds

### How It Hunts:
1. **Technology Fingerprinting**: Identifies server tech to avoid SPA false positives
2. **Parameter Discovery**: Maps every injection point in the application
3. **Payload Injection**: Tests multiple payload types with evasion techniques
4. **Response Analysis**: Differentiates between real vulnerabilities and dead ends
5. **Exploitation Mapping**: Builds attack paths based on discovered weaknesses

### Advanced Techniques:
- **Context-Aware Payloads**: Adapts to different SQL dialects
- **Heuristic Analysis**: Learns from target responses
- **Progressive Depth**: Goes deeper when it finds openings
- **Adaptive Timing**: Adjusts to target response patterns

<div align="center">

### **by ek0ms savi0r**

**SQLMaster** - When you absolutely, positively need to know if that database is vulnerable and then exploit it!

![Hack the Planet](https://img.shields.io/badge/Hack_The_Planet-red)

</div>
