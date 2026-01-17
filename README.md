# O.R.C.A.
full-stack open source Automated MDR(SIEM + SOAR + Case Management + DFIR + FIrewall + IDS/IPS +Threat Intelligence)
# Wazuh + TheHive + Cortex + MISP

This repository provides a **complete installation and integration guide** for building an open‑source SOC stack using:

- **Wazuh** – SIEM & EDR
- **TheHive** – Incident Response & Case Management
- **Cortex** – Observable Analysis & Response
- **MISP** – Threat Intelligence Platform

The guide covers:
- Individual installation steps
- Required prerequisites
- End‑to‑end integrations:
  - Wazuh → TheHive
  - TheHive → Cortex
  - TheHive ↔ MISP

---

## Architecture Overview

```
Endpoints → Wazuh Agent → Wazuh Manager
                              ↓
                          TheHive
                           ↓   ↓
                        Cortex  MISP
```

---

## System Requirements

| Component | Minimum Requirements |
|--------|----------------------|
| OS | Ubuntu 20.04 / 22.04 LTS |
| RAM | 16 GB (32 GB recommended) |
| CPU | 8 vCPU |
| Disk | 200 GB SSD |
| Java | OpenJDK 11 |
| Python | 3.8+ |

> ⚠️ **All components should ideally be installed on separate servers for production**

---

## 1. Wazuh Installation

### 1.1 Install Wazuh Manager

```bash
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash wazuh-install.sh -a
```

Services installed:
- wazuh-manager
- wazuh-indexer
- wazuh-dashboard

Access Dashboard:
```
https://<WAZUH_IP>:5601
```

---

### 1.2 Install Wazuh Agent (Endpoint)

```bash
curl -sO https://packages.wazuh.com/4.x/wazuh-agent.sh
sudo bash wazuh-agent.sh
```

Register Agent:
```bash
/var/ossec/bin/agent-auth -m <WAZUH_MANAGER_IP>
```

---

## 2. TheHive Installation

### 2.1 Install Dependencies

```bash
sudo apt update
sudo apt install -y openjdk-11-jre-headless wget gnupg apt-transport-https
```

### 2.2 Install Cassandra

```bash
sudo apt install cassandra -y
sudo systemctl enable cassandra
sudo systemctl start cassandra
```

### 2.3 Install TheHive

```bash
wget -qO- https://deb.thehive-project.org/thehive-project.gpg.key | sudo apt-key add -
echo "deb https://deb.thehive-project.org release main" | sudo tee /etc/apt/sources.list.d/thehive-project.list
sudo apt update
sudo apt install thehive4 -y
```

Start Service:
```bash
sudo systemctl enable thehive
sudo systemctl start thehive
```

Access:
```
http://<THEHIVE_IP>:9000
```

---

## 3. Cortex Installation

### 3.1 Install Cortex

```bash
sudo apt install cortex -y
```

### 3.2 Configure Cortex

Edit:
```bash
/etc/cortex/application.conf
```

Set:
```hocon
play.http.secret.key="change_this_key"
```

Start:
```bash
sudo systemctl enable cortex
sudo systemctl start cortex
```

Access:
```
http://<CORTEX_IP>:9001
```

---

## 4. MISP Installation

### 4.1 Automated Install (Recommended)

```bash
curl https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh -o misp_install.sh
sudo bash misp_install.sh
```

Access:
```
https://<MISP_IP>
```

Create API Key:
```
Administration → Automation → Add API Key
```

---

## 5. Integration Steps

---

## 5.1 Wazuh → TheHive Integration

### Purpose
Automatically create **alerts/cases in TheHive** from Wazuh alerts.

### Steps

#### 1. Install TheHive Python Client on Wazuh Manager

```bash
pip3 install thehive4py
```

#### 2. Create Integration Script

Location:
```
/var/ossec/integrations/custom-wazuh-thehive.py
```

Configure:
- TheHive URL
- API Key
- Alert mapping

#### 3. Update Wazuh Integration Config

Edit:
```bash
/var/ossec/etc/ossec.conf
```

Add:
```xml
<integration>
  <name>custom-wazuh-thehive</name>
  <hook_url>http://<THEHIVE_IP>:9000</hook_url>
  <api_key>THEHIVE_API_KEY</api_key>
  <alert_format>json</alert_format>
</integration>
```

Restart:
```bash
systemctl restart wazuh-manager
```

✅ Wazuh alerts now appear in TheHive

---

## 5.2 TheHive → Cortex Integration

### Purpose
Run automated **analyzers & responders** from TheHive.

### Steps

#### 1. Create Cortex API Key

```
Cortex → Organization → Users → Create API Key
```

#### 2. Configure TheHive

Edit:
```bash
/etc/thehive/application.conf
```

Add:
```hocon
cortex {
  servers = [
    {
      name = "local-cortex"
      url = "http://<CORTEX_IP>:9001"
      auth {
        type = "bearer"
        key = "CORTEX_API_KEY"
      }
    }
  ]
}
```

Restart:
```bash
systemctl restart thehive
```

✅ Cortex analyzers visible inside TheHive

---

## 5.3 TheHive ↔ MISP Integration

### Purpose
- Import IOCs from MISP
- Export confirmed indicators back to MISP

### Steps

#### 1. Create MISP API Key

```
MISP → Administration → Automation → Add Key
```

#### 2. Configure TheHive

Edit:
```bash
/etc/thehive/application.conf
```

Add:
```hocon
misp {
  servers = [
    {
      name = "local-misp"
      url = "https://<MISP_IP>"
      auth {
        type = "key"
        key = "MISP_API_KEY"
      }
      wsConfig {
        insecure = true
      }
    }
  ]
}
```

Restart:
```bash
systemctl restart thehive
```

✅ MISP feeds & export available in TheHive

---

## 6. Validation Checklist

- [ ] Wazuh agent sending alerts
- [ ] Wazuh dashboard shows events
- [ ] Alerts appear in TheHive
- [ ] Cortex analyzers executable
- [ ] MISP IOCs import/export works

---

## 7. Common Issues

| Issue | Fix |
|-----|-----|
| Alerts not sent to TheHive | Check API key & integration script |
| Cortex analyzers missing | Enable analyzers in Cortex UI |
| MISP SSL error | Set `insecure=true` |

---

## 8. Security Best Practices

- Use HTTPS everywhere
- Rotate API keys regularly
- Separate services on different hosts
- Restrict API access by IP

---

## 9. References

- Wazuh Documentation
- TheHive Project Docs
- Cortex Analyzers GitHub
- MISP Documentation

---

### ✅ SOC Stack Ready
This setup provides **SIEM + Case Management + Automation + Threat Intel** for blue team operations.

---

If you want:
- Sample scripts
- Docker‑based deployment
- SOAR automation (Shuffle / n8n)

Just ask 🚀

