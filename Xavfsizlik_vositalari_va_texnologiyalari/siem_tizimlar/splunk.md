# Splunk — To'liq qoʻllanma va ishlatilishi

> Ushbu hujjat Splunkni **oʻrnatish, konfiguratsiya, maʼlumotlarni ingest qilish, search, dashboardlar, alertlar, SIEM integratsiyasi va amaliy misollar** bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Linux misol)
4. Splunk ishga tushirish va boshqaruv
5. Data ingest qilish
6. Search va reporting
7. Dashboard va vizualizatsiya
8. Alert va notification
9. Performance tuning
10. Test va validatsiya
11. Amaliy misollar
12. Common muammolar va yechimlar
13. Qo'shimcha resurslar

---

## 1. Tez xulosa

Splunk — maʼlumotlarni toʻplash, indekslash, qidirish va vizualizatsiya qilish uchun keng qo‘llaniladigan platforma. U:

* Logs, metrics, network data, security events va boshqa manbalarni qabul qiladi
* Real-time search, alert va dashboard imkoniyatlari bor
* SIEM va tahlil platformalari bilan integratsiya qilinadi

---

## 2. Kerakli talablar

* Linux (Ubuntu/Debian/RHEL/CentOS) yoki Windows
* Minimal 4GB RAM (real deploymentda 8GB+), CPU 2+ core
* Disk: loglar va indexlar uchun SSD tavsiya qilinadi

---

## 3. Oʻrnatish (Linux misol)

Rasmiy Splunk paketlari .tgz yoki .deb orqali o‘rnatiladi:

```bash
# Paket yuklash (Debian/Ubuntu)
wget -O splunk-9.1.0.deb 'https://www.splunk.com/page/download_track?file=...'
sudo dpkg -i splunk-9.1.0.deb
```

Ruxsatlarni sozlash:

```bash
sudo /opt/splunk/bin/splunk start --accept-license
sudo /opt/splunk/bin/splunk enable boot-start
```

---

## 4. Splunk ishga tushirish va boshqaruv

* Web interfeys: `http://<server_ip>:8000`
* CLI: `/opt/splunk/bin/splunk`

Asosiy buyruqlar:

```bash
# Status
sudo /opt/splunk/bin/splunk status
# Start
sudo /opt/splunk/bin/splunk start
# Stop
sudo /opt/splunk/bin/splunk stop
# Restart
sudo /opt/splunk/bin/splunk restart
```

---

## 5. Data ingest qilish

* Manbalar: log fayllar, syslog, Windows Event, API, network data
* Inputs qo‘shish:

```bash
sudo /opt/splunk/bin/splunk add monitor /var/log/syslog -index main
sudo /opt/splunk/bin/splunk add tcp 514 -sourcetype syslog
```

* Forwarder yordamida remote serverlardan log yig‘ish

---

## 6. Search va reporting

* SPL (Search Processing Language) bilan data qidirish
* Oddiy misol:

```splunk
index=main sourcetype=syslog ERROR | stats count by host
```

* Reporting va chart yaratish imkoniyatlari mavjud

---

## 7. Dashboard va vizualizatsiya

* Splunk Web orqali drag & drop dashboardlar
* Charts, tables, single-value, map va heatmap vizualizatsiya
* Dynamic dashboardlar SPL search va drill-down qo‘llab-quvvatlaydi

---

## 8. Alert va notification

* Realtime yoki scheduled alerts
* E-mail, webhook, script orqali notification
* Misol: 5 daqiqa davomida ERROR loglar soni 50 dan oshsa alert:

```splunk
index=main sourcetype=syslog ERROR | stats count by host | where count>50
```

---

## 9. Performance tuning

* Indexing strategy va retention periodni sozlash
* Heavy forwarder va indexer rollarini ajratish
* CPU, memory, disk IO monitoring

---

## 10. Test va validatsiya

* Sample log fayllarni ingest qilib qidiruvni tekshirish
* Alert va dashboard ishlashini test qilish
* Forwarder orqali remote log test

---

## 11. Amaliy misollar

### a) Local syslog monitoring

```bash
sudo /opt/splunk/bin/splunk add monitor /var/log/syslog -index main -sourcetype syslog
```

### b) Windows Event monitoring

* Universal Forwarder o‘rnatish
* Event log forward qilish

### c) Dashboard yaratish

* Web GUI → Dashboards → Create New Dashboard → Add Panel
* Panel type: Chart/Table
* Source: SPL search query

### d) Alert yaratish

* Web GUI → Alerts → Create New Alert → Set condition (Realtime/Scheduled)
* Action: Email/Webhook/Script

---

## 12. Common muammolar va yechimlar

* **Loglar ingest bo‘lmayapti** → Input path va permissionsni tekshirish
* **Performance past** → Indexer va search head ajratish, retention period qisqartirish
* **Alert ishlamayapti** → SPL query va time range tekshirish

---

## 13. Qo'shimcha resurslar

* [Splunk Documentation](https://docs.splunk.com/)
* [Splunk Answers](https://community.splunk.com/)
* Splunk blogs va GitHub repository misollari
* SIEM integratsiyasi va dashboard tutoriallari

---

> Splunk tahlil va vizualizatsiya platformasi sifatida, log va tarmoq monitoring, alertlar va dashboardlar orqali tahlil imkoniyatlarini kengaytiradi.
