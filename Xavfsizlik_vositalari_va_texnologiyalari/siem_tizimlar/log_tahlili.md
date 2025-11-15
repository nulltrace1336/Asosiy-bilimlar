# Log Tahlili — To'liq qoʻllanma

> Ushbu hujjat log tahlilini **asosiy tushunchalar, turli log turlari, analiz usullari, SIEM integratsiyasi, amaliy misollar va tavsiyalar** bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Log turlari
3. Log yig‘ish va saqlash
4. Log analiz usullari
5. SIEM integratsiyasi
6. Log tahlil vositalari
7. Performance va xavfsizlik
8. Amaliy misollar
9. Common muammolar va yechimlar
10. Qo'shimcha resurslar

---

## 1. Tez xulosa

Log tahlili — tizim, tarmoq va ilovalar tomonidan hosil qilingan loglarni yig‘ish, indekslash, tahlil qilish va xavfsizlik yoki operatsion qarorlar qabul qilish jarayonidir.

---

## 2. Log turlari

* **System logs**: OS eventlar (`/var/log/syslog`, Windows Event Log)
* **Security logs**: firewall, IDS/IPS, antivirus, access logs
* **Application logs**: web server (Apache/Nginx), DB logs, custom apps
* **Network logs**: Suricata, Zeek, Cisco ASA, Fortigate
* **Audit logs**: compliance va monitoring uchun (PCI, HIPAA)

---

## 3. Log yig‘ish va saqlash

* Centralized log server (rsyslog, syslog-ng, Wazuh, ELK)
* Forwarder: Filebeat, Winlogbeat
* Log rotation va retention policy
* Security: TLS/SSL, access control

---

## 4. Log analiz usullari

* **Manual inspection**: `cat`, `grep`, `awk`, `less`
* **Pattern detection**: regex, log parsing
* **Correlation**: multiple logs tahlil qilish
* **Anomaly detection**: threshold, ML-based detection
* **Trend analysis**: frequency, peak hours, error spikes

---

## 5. SIEM integratsiyasi

* Splunk, ELK/Elastic SIEM, Wazuh
* Real-time alerts va dashboards
* Correlation rules va incident response
* Threat intelligence feeds bilan integratsiya

---

## 6. Log tahlil vositalari

* **CLI tools**: grep, awk, sed, cut, tail, less
* **SIEM**: Splunk, ELK/Elastic SIEM, Wazuh
* **Network IDS logs**: Suricata, Zeek, Snort
* **Visual tools**: Kibana, Grafana, Splunk dashboards

---

## 7. Performance va xavfsizlik

* Log storage optimizatsiyasi (index, compression, rotation)
* Access control va audit logging
* High throughput uchun log shipper va buffer
* Log integrity va tamper detection

---

## 8. Amaliy misollar

### a) Linux syslog tahlili

```bash
# Oxirgi 100 ta xatolikni ko'rish
grep -i error /var/log/syslog | tail -n 100
```

### b) Web server log tahlili

```bash
# Apache access logda 404 status count
awk '$9 == 404 {count++} END {print count}' /var/log/apache2/access.log
```

### c) Suricata log analiz

```bash
jq '.alert | {signature, src_ip, dest_ip}' /var/log/suricata/eve.json
```

### d) SIEM query (Splunk misol)

```splunk
index=main sourcetype=syslog ERROR | stats count by host
```

---

## 9. Common muammolar va yechimlar

* **Loglar kelmayapti** → paths, permissions, network port
* **Performance past** → index optimization, multi-threading, SSD
* **False-positive alertlar** → rule optimization, thresholding

---

## 10. Qo'shimcha resurslar

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Splunk Docs](https://docs.splunk.com/)
* [Elastic SIEM Docs](https://www.elastic.co/solutions/siem)
* Blogs va GitHub misollari

---

> Log tahlili tizim monitoringi, xavfsizlik va compliance jarayonlarini samarali boshqarish uchun muhimdir, turli log turlari va vositalar yordamida real-time va historik tahlil qili
