# ELK / Elastic SIEM — To'liq qoʻllanma

> Ushbu hujjat ELK (Elasticsearch, Logstash, Kibana) stack va Elastic SIEMni **o‘rnatish, konfiguratsiya, log ingest, dashboardlar, alertlar va amaliy misollar** bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Ubuntu/Debian misol)
4. Elasticsearch konfiguratsiyasi
5. Logstash konfiguratsiyasi
6. Filebeat / data shipper
7. Kibana va SIEM app
8. Dashboard va vizualizatsiya
9. Alert va notification
10. Performance tuning
11. Test va validatsiya
12. Amaliy misollar
13. Common muammolar va yechimlar
14. Qo'shimcha resurslar

---

## 1. Tez xulosa

ELK stack (Elasticsearch, Logstash, Kibana) — loglar va tarmoq ma’lumotlarini yig‘ish, indekslash, qidirish va vizualizatsiya qilish platformasi.

* Elasticsearch: loglarni saqlash va qidiruv
* Logstash: logni transformatsiya va ingest
* Kibana: dashboard, visualizatsiya va SIEM
* Filebeat / Metricbeat: log va metriks shipper
* Elastic SIEM: security monitoring, detections va alerts

---

## 2. Kerakli talablar

* Linux (Ubuntu/Debian/RHEL/CentOS)
* Minimal 8GB RAM (real deployment 16GB+)
* SSD disk, ko‘p CPU core
* Java (Logstash va Elasticsearch uchun) — rasmiy talabni tekshiring

---

## 3. Oʻrnatish (Ubuntu/Debian misol)

Elasticsearch o‘rnatish:

```bash
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.11.0-amd64.deb
sudo dpkg -i elasticsearch-8.11.0-amd64.deb
sudo systemctl enable --now elasticsearch
```

Logstash o‘rnatish:

```bash
wget https://artifacts.elastic.co/downloads/logstash/logstash-8.11.0.deb
sudo dpkg -i logstash-8.11.0.deb
sudo systemctl enable --now logstash
```

Kibana o‘rnatish:

```bash
wget https://artifacts.elastic.co/downloads/kibana/kibana-8.11.0-amd64.deb
sudo dpkg -i kibana-8.11.0-amd64.deb
sudo systemctl enable --now kibana
```

---

## 4. Elasticsearch konfiguratsiyasi

* `elasticsearch.yml` sozlamalari `/etc/elasticsearch/elasticsearch.yml`
* Cluster name, node name, network.host, memory limits
* Security: TLS/SSL va user/password

---

## 5. Logstash konfiguratsiyasi

* Pipeline fayllari `/etc/logstash/conf.d/`
* Input, filter va output bloklari

Misol `syslog.conf`:

```conf
input {
  beats {
    port => 5044
  }
}
filter {
  grok {
    match => { "message" => "%{SYSLOGLINE}" }
  }
}
output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "syslog-%{+YYYY.MM.dd}"
  }
}
```

---

## 6. Filebeat / data shipper

* Log va tarmoq data (Suricata, Zeek, Syslog) yuborish uchun ishlatiladi
* Misol `filebeat.yml`:

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/suricata/eve.json
output.logstash:
  hosts: ["localhost:5044"]
```

* Service start:

```bash
sudo systemctl enable --now filebeat
```

---

## 7. Kibana va SIEM app

* Kibana web GUI: `http://<server_ip>:5601`
* Security App (SIEM) → Detection, Timeline, Cases
* Dashboard yaratish va visualizatsiya uchun drag & drop

---

## 8. Dashboard va vizualizatsiya

* Charts, tables, maps, heatmaps
* Custom dashboardlar SPL/Elasticsearch queries bilan yaratiladi
* Realtime data monitoring

---

## 9. Alert va notification

* Elastalert yoki Kibana alert engine orqali
* Realtime yoki scheduled alerts
* Action: Email, webhook, script

---

## 10. Performance tuning

* Elasticsearch JVM heap (RAM 50% limit) sozlash
* Index sharding va replication
* Logstash pipeline threads
* Disk I/O va SSD ishlatish

---

## 11. Test va validatsiya

* Sample log fayllarni ingest qilib tekshirish
* Kibana dashboard va alerts ishlashini tekshirish
* Filebeat forwarder test

---

## 12. Amaliy misollar

### a) Suricata loglarni ingest qilish

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/suricata/eve.json
output.logstash:
  hosts: ["localhost:5044"]
```

### b) Syslog monitoring

* Filebeat + Logstash + Elasticsearch pipeline
* Index: `syslog-%{+YYYY.MM.dd}`

### c) Kibana SIEM alert

* Dashboard → Detection → Create new rule → Condition (e.g., Suricata alert > 5 daqiqa)
* Action: Email notification

---

## 13. Common muammolar va yechimlar

* **Loglar kelmayapti** → Input path, file permissions, network port
* **Performance past** → Elasticsearch heap, index shards, SSD ishlatish
* **Alert ishlamayapti** → Condition va time range tekshirish

---

## 14. Qo'shimcha resurslar

* [Elastic documentation](https://www.elastic.co/guide/index.html)
* [Elastic SIEM documentation](https://www.elastic.co/solutions/siem)
* Blogs, forum va GitHub misollari

---

> ELK / Elastic SIEM loglar, security events va tarmoq monitoring uchun kuchli platforma bo‘lib, data ingest, search, dashboard va ale
