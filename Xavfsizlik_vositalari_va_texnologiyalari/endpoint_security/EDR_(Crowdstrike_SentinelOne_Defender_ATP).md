# EDR (Endpoint Detection & Response) — To'liq qoʻllanma

> Ushbu hujjat EDR tizimlari (CrowdStrike, SentinelOne, Defender ATP) ni **asosiy tushunchalari, o‘rnatish, konfiguratsiya, monitoring, threat detection va amaliy ishlatilishi** bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. EDR tushunchasi
3. CrowdStrike Falcon
4. SentinelOne
5. Microsoft Defender ATP
6. Agent konfiguratsiyasi va deployment
7. Threat detection va response
8. SIEM integratsiyasi
9. Performance va security considerations
10. Amaliy misollar
11. Common muammolar va yechimlar
12. Qo'shimcha resurslar

---

## 1. Tez xulosa

EDR (Endpoint Detection & Response) — endpointlarni monitoring qilish, real-time threat detection, incident response va forensics imkoniyatlarini taqdim etadigan xavfsizlik platformasi. U:

* Endpoint behavior monitoring
* Malware, ransomware va exploit detection
* Threat hunting va incident investigation
* SIEM va SOC integratsiyasi

---

## 2. EDR tushunchasi

* Endpoint monitoring: processes, files, network connections
* Detection: signature-based, behavioral-based, ML-based
* Response: quarantine, isolate device, terminate process
* Reporting: alerts, dashboards, forensic data

---

## 3. CrowdStrike Falcon

* Cloud-native EDR platforma
* Features: Real-time prevention, detection, response
* Deployment: lightweight agent Windows/Linux/Mac
* Dashboard va console orqali monitoring va response
* Integration: SIEM (Splunk, ELK), threat intelligence

### CrowdStrike Agent deployment

```bash
# Windows: MSI installer
msiexec /i CrowdStrikeFalcon.msi CID=<CustomerID>

# Linux: .rpm/.deb package
sudo dpkg -i falcon-sensor.deb
sudo systemctl enable --now falcon-sensor
```

---

## 4. SentinelOne

* Autonomous EDR with ML-based detection
* Features: behavior analysis, rollback, quarantine, threat hunting
* Agent-based deployment (Windows/Linux/Mac)
* Console provides dashboards, alerts, response actions

### SentinelOne Agent deployment

```bash
# Windows: MSI installer with management console token
msiexec /i SentinelOneAgent.msi SITE_TOKEN=<token>

# Linux: RPM/DEB package
sudo rpm -i sentinel-agent.rpm
sudo systemctl enable --now sentinel-agent
```

---

## 5. Microsoft Defender ATP (Defender for Endpoint)

* Built-in Windows EDR solution
* Features: attack surface reduction, endpoint behavioral sensors, alerts, automated investigation
* Integration with Microsoft 365 Security Center and SIEM
* Deployment via Intune, SCCM or local Group Policy

---

## 6. Agent konfiguratsiyasi va deployment

* Windows, Linux, Mac uchun agent paketlari
* Deployment: MSI, RPM, DEB, via SCCM, Intune yoki manual
* Central management console orqali policies, updates va alerts boshqarish
* Network ports va firewall rules tekshirish zarur

---

## 7. Threat detection va response

* Behavioral monitoring, signature, ML detection
* Actions: quarantine file, isolate endpoint, terminate process
* Real-time alerts: console, email, webhook
* Investigation: event log, process tree, file hashes

---

## 8. SIEM integratsiyasi

* CrowdStrike, SentinelOne, Defender ATP loglar SIEMga yuborish
* Splunk, ELK, Wazuh orqali visualization va correlation
* Automated alerts va dashboards

---

## 9. Performance va security considerations

* Agent CPU, memory usage monitoring
* Network impact minimalizatsiyasi
* Secure communication with cloud console
* Multi-tenancy and role-based access

---

## 10. Amaliy misollar

### a) CrowdStrike alert monitoring

* Falcon console → Threats → Investigate
* Alert response: isolate endpoint, submit file for analysis

### b) SentinelOne rollback example

* Detect ransomware behavior
* Rollback affected files via console action

### c) Defender ATP detection

* Security Center → Incidents → Investigate alert
* Automated remediation (kill process, isolate device)

---

## 11. Common muammolar va yechimlar

* **Agent ulamayapti** → firewall, ports, management console connection
* **Alerts kelmayapti** → agent health, log forwarding, console configuration
* **Performance past** → agent resource usage optimization
* **False positives** → tune detection policies, ML thresholds

---

## 12. Qo'shimcha resurslar

* [CrowdStrike Falcon Documentation](https://www.crowdstrike.com/resources/)
* [SentinelOne Documentation](https://www.sentinelone.com/documentation/)
* [Microsoft Defender for Endpoint](https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/)
* Community forums, GitHub integration examples

---

> EDR tizimlari endpoint monitoringi, threat detection va automated response orqali tashkilot xavfsizligini sezilarli darajada oshiradi, real-time tahlil va SIEM integratsiyasi bilan SOC operatsiyalarini optimallas
