# Anomaliyalarni Topish — To'liq qoʻllanma

> Ushbu hujjat anomaliyalarni topish (Anomaly Detection) usullari, amaliy ishlatilishi, loglar va SIEM integratsiyasi, tahlil metodlari va misollar bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Anomaliya tushunchasi
3. Anomaliyalarni aniqlash usullari
4. Data manbalari
5. SIEM va log integratsiyasi
6. Tools va platformalar
7. Amaliy tahlil metodlari
8. Test va validatsiya
9. Amaliy misollar
10. Common muammolar va yechimlar
11. Qo'shimcha resurslar

---

## 1. Tez xulosa

Anomaliyalarni topish — bu normal holatga mos kelmaydigan, kutilmagan yoki xavfli faoliyatni aniqlash jarayoni. U:

* Security monitoring (IDS/IPS, SIEM)
* Operational monitoring (server, tarmoq, app)
* Fraud detection (moliyaviy operatsiyalar)
* Predictive maintenance (IoT, sensor data)

---

## 2. Anomaliya tushunchasi

* **Point anomalies**: individual data point normaldan chetda
* **Contextual anomalies**: ma’lum kontekstda anormal (vaqt, lokatsiya)
* **Collective anomalies**: o‘zaro bog‘liq data to‘plami normaldan chetda

---

## 3. Anomaliyalarni aniqlash usullari

* **Statistical methods**: mean, std deviation, z-score, percentile
* **Machine Learning**:

  * Supervised: classification-based anomaly detection
  * Unsupervised: clustering, isolation forest, autoencoders
* **Rule-based**: threshold, frequency analysis
* **Time-series analysis**: ARIMA, seasonal decomposition, moving average

---

## 4. Data manbalari

* System logs: `/var/log/syslog`, Windows Event Log
* Network logs: Zeek, Suricata, firewall logs
* Application logs: web server, DB, custom apps
* Metrics: CPU, memory, disk I/O, network traffic

---

## 5. SIEM va log integratsiyasi

* Splunk, ELK/Elastic SIEM, Wazuh
* Real-time alerts va dashboards
* Correlation rules orqali anomal activity aniqlash
* Threat intelligence feeds bilan integratsiya

---

## 6. Tools va platformalar

* **CLI tools**: grep, awk, jq, tail
* **SIEM platforms**: Splunk, ELK, Wazuh
* **ML libraries**: scikit-learn, TensorFlow, PyTorch
* **Visualization**: Kibana, Grafana, Splunk dashboards

---

## 7. Amaliy tahlil metodlari

* Data preprocess: normalize, clean, timestamp align
* Thresholding: log count, error rate, failed login attempts
* Statistical detection: z-score, moving average
* ML-based: clustering, isolation forest, autoencoder
* Time-series anomaly detection for network or app metrics

---

## 8. Test va validatsiya

* Sample loglar va traffic replay
* Known attack / anomaly simulation
* Check alerts, dashboards, SIEM correlation results

---

## 9. Amaliy misollar

### a) Linux syslog anomaliya detection

```bash
# 1 soat ichida ERROR loglar sonini hisoblash
grep -i error /var/log/syslog | awk -v date="$(date +%Y-%m-%d)" '$0 ~ date {count++} END {print count}'
```

### b) Suricata log anomaliyasi

```bash
# 1 daqiqada ko'p uchraydigan signature
jq '.alert.signature' /var/log/suricata/eve.json | sort | uniq -c | sort -nr | head
```

### c) Splunk alert example

```splunk
index=main sourcetype=syslog ERROR | stats count by host | where count > 50
```

* 50 dan oshgan xatoliklar anomaliya sifatida alert beradi

### d) Python ML-based anomaly detection

```python
from sklearn.ensemble import IsolationForest
X = [[error_count, login_fail]]
clf = IsolationForest().fit(X)
pred = clf.predict(X)  # -1 anomaliya, 1 normal
```

---

## 10. Common muammolar va yechimlar

* **False positives** → threshold va rules optimizatsiyasi
* **Performance past** → indexing, log rotation, multi-threaded processing
* **Loglar yetarli emas** → log collection va shipper tekshirish

---

## 11. Qo'shimcha resurslar

* [Splunk anomaly detection](https://docs.splunk.com/Documentation/Splunk/latest/Search/Anomalydetection)
* [Elastic ML](https://www.elastic.co/guide/en/machine-learning/current/index.html)
* [Wazuh anomaly detection](https://documentation.wazuh.com/current/user-manual/capabilities/anomaly-detection.html)
* Blogs, GitHub misollar, ML tutorials

---

> Anomaliyalarni topish tizim monitoringi, xavfsizlik va operational tahlil uchun muhim bo‘lib, turli usullar va vositalar yordamida real-time va historik tahlil qilish imkonini beradi.
