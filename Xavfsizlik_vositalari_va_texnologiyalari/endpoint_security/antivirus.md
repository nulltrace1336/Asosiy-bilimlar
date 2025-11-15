# Antiviruses — To'liq qoʻllanma

> Ushbu hujjat antivirus dasturlari va ularning ishlatilishi, o‘rnatish, konfiguratsiya, scanning, real-time protection va amaliy misollar bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Antivirus tushunchasi
3. Eng mashhur antiviruslar
4. Oʻrnatish va konfiguratsiya
5. Real-time monitoring
6. Manual scanning
7. Scheduled scanning
8. Threat detection va response
9. SIEM integratsiyasi
10. Performance va xavfsizlik
11. Amaliy misollar
12. Common muammolar va yechimlar
13. Qo'shimcha resurslar

---

## 1. Tez xulosa

Antivirus dasturlari — endpointlarni viruslar, malware, ransomware va boshqa zararli dasturlardan himoya qilish uchun mo‘ljallangan dasturiy ta’minotdir. Ular:

* Real-time monitoring
* Threat scanning
* Quarantine va remediation
* Reporting va logs

---

## 2. Antivirus tushunchasi

* **Real-time protection**: fayllar, jarayonlar va tarmoqlarni doimiy monitoring
* **Scanning**: manual yoki scheduled fayl va tizim scan
* **Threat response**: quarantine, delete, repair
* **Update**: virus signature va patternlarni yangilash

---

## 3. Eng mashhur antiviruslar

* Windows Defender (Microsoft)
* Kaspersky, ESET, Norton, Bitdefender
* Avast, AVG, Sophos
* Open-source: ClamAV

---

## 4. Oʻrnatish va konfiguratsiya

* **Windows**: installer fayl orqali o‘rnatish, update va policies sozlash
* **Linux**: ClamAV, ESET endpoint, Sophos CLI
* **Mac**: Bitdefender, Norton, Avast installer

### Misol: ClamAV Linux o‘rnatish

```bash
sudo apt update
sudo apt install clamav clamav-daemon
sudo systemctl enable --now clamav-freshclam
sudo freshclam  # virus definitions update
```

---

## 5. Real-time monitoring

* Background process monitoring, fayl va jarayonlarni kuzatish
* Windows Defender, ESET, CrowdStrike kabi EDR bilan integratsiya qilinadi
* Logs saqlash va alert yaratish imkoniyati

---

## 6. Manual scanning

```bash
# ClamAV Linux misol
clamscan -r /home/user
# Windows Defender PowerShell
Start-MpScan -ScanType FullScan
```

---

## 7. Scheduled scanning

* Cron (Linux) yoki Task Scheduler (Windows) orqali
* Regular scan frequency: daily, weekly, monthly
* Notification: email yoki SIEM alert

---

## 8. Threat detection va response

* Quarantine infected files
* Delete yoki repair infected files
* Alert SOC / SIEM
* Reporting: detected, remediated, false positives

---

## 9. SIEM integratsiyasi

* Antivirus logs SIEMga yuborish (Splunk, ELK, Wazuh)
* Real-time alerts va dashboards
* Threat correlation va incident response

---

## 10. Performance va xavfsizlik

* Scan frequency va scopeni optimizatsiya qilish
* Resource usage (CPU, RAM) monitoring
* Update va signature management
* Secure log forwarding

---

## 11. Amaliy misollar

### a) ClamAV Linux scan

```bash
clamscan -r /var/log
```

### b) Windows Defender full scan

```powershell
Start-MpScan -ScanType FullScan
```

### c) Scheduled scan example (Linux cron)

```bash
0 2 * * * clamscan -r /home/user >> /var/log/clamav_scan.log
```

### d) SIEM log forwarding

* Filebeat + ELK

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/clamav_scan.log
output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "antivirus-logs-%{+YYYY.MM.dd}"
```

---

## 12. Common muammolar va yechimlar

* **Update qilinmayapti** → internet, repo va permissions tekshirish
* **Scan performance past** → scope va frequency optimizatsiya
* **False positives** → whitelisting, exclusion paths
* **Logs kelmayapti SIEMga** → paths, permissions, shipper konfiguratsiyasi

---

## 13. Qo'shimcha resurslar

* [ClamAV Documentation](https://www.clamav.net/documents)
* [Windows Defender Docs](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-antivirus/windows-defender-antivirus-in-windows-10)
* [Kaspersky Endpoint Security](https://support.kaspersky.com/)
* [Splunk Antivirus log integration](https://docs.splunk.com/Documentation/Splunk/latest/Data/MonitorWindowsDefender)

---

> Antivirus dasturlari endpointlarni zararli dasturlardan himoya qiladi, real-time monitoring, scanning, threat response va SIEM integratsiyasi orqali xavfsizli
