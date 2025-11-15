# Wazuh — To'liq qoʻllanma

> Ushbu hujjat Wazuh SIEM va Endpoint Security platformasini **o‘rnatish, konfiguratsiya, agentlar, alertlar, dashboard, log integratsiyasi va amaliy misollar** bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Wazuh Server va Agent)
4. Agent konfiguratsiyasi
5. Rule va alertlar
6. Log integratsiyasi
7. Dashboard va vizualizatsiya
8. Performance tuning
9. Test va validatsiya
10. Amaliy misollar
11. Common muammolar va yechimlar
12. Qo'shimcha resurslar

---

## 1. Tez xulosa

Wazuh — ochiq manbali SIEM va endpoint security platformasi. U:

* Real-time host monitoring
* Log management va threat detection
* Compliance monitoring (PCI-DSS, GDPR, HIPAA)
* Integration: ELK/Kibana bilan vizualizatsiya
* Agent va agentless monitoring imkoniyatlari

---

## 2. Kerakli talablar

* Linux (Ubuntu/Debian/RHEL/CentOS) yoki Windows server
* Minimal 4GB RAM (real deployment 8GB+)
* CPU: 2+ core
* Disk: SSD tavsiya qilinadi (logs va indexes uchun)

---

## 3. Oʻrnatish (Server va Agent)

### Wazuh Server (Ubuntu misol)

```bash
# Repository qo'shish
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo apt install wazuh-manager
```

### Wazuh Agent (Linux misol)

```bash
sudo apt install wazuh-agent
sudo systemctl enable --now wazuh-agent
```

### Agent Windows misol

* MSI installer orqali agent o‘rnatiladi
* Configuration fayli: `C:\Program Files (x86)\Wazuh\agent\ossec.conf`

---

## 4. Agent konfiguratsiyasi

* `ossec.conf` ichida server IP va port sozlanadi

```xml
<client>
  <server>
    <address>192.168.1.100</address>
    <port>1514</port>
  </server>
</client>
```

* Agent key bilan managerga register qilinadi:

```bash
/var/ossec/bin/agent-auth -m <manager_ip> -p 1515
```

---

## 5. Rule va alertlar

* Rules: `/var/ossec/rules/` papkada
* Alerts: `/var/ossec/logs/alerts/alerts.json`
* Custom rules yaratish va alerts sozlash mumkin
* Misol rule:

```xml
<group name="custom-alerts">
  <rule id="100001" level="10">
    <decoded_as>json</decoded_as>
    <field name="event.type">login_failure</field>
    <description>Multiple failed login attempts</description>
  </rule>
</group>
```

---

## 6. Log integratsiyasi

* ELK stack bilan integratsiya:

  * Elasticsearch indexlar
  * Kibana dashboards
* Filebeat orqali Wazuh loglarni ingest qilish:

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/ossec/logs/alerts/alerts.json
output.elasticsearch:
  hosts: ["localhost:9200"]
  index: "wazuh-alerts-%{+YYYY.MM.dd}"
```

---

## 7. Dashboard va vizualizatsiya

* Kibana → Wazuh App
* Dashboard: Security Events, Agents Status, Compliance Reports
* Custom visualizations va alerts yaratish mumkin

---

## 8. Performance tuning

* Wazuh manager va agent resurslarini monitoring qilish
* Log rotation va compress
* Elasticsearch index optimizatsiyasi
* Multi-threading va cluster deployment (large-scale)

---

## 9. Test va validatsiya

* Agent va server statusni tekshirish:

```bash
sudo /var/ossec/bin/agent_control -l
```

* Test alert yaratish:

```bash
echo '{"event.type": "login_failure", "user": "test"}' > /var/ossec/logs/alerts/test.json
```

* Kibana dashboardda alertni tekshirish

---

## 10. Amaliy misollar

### a) Agent monitoring

* Serverga agent qo‘shish, status tekshirish

### b) Custom alert rule

* `/var/ossec/rules/custom_rules.xml` yaratish, Wazuh restart

### c) ELK integratsiya

* Filebeat input konfiguratsiyasi, index va dashboard yaratish

---

## 11. Common muammolar va yechimlar

* **Agent ulamayapti** → network port va firewall tekshirish
* **Alerts kelmayapti** → rules va ossec.log tekshirish
* **Performance past** → Elasticsearch heap, Wazuh manager threads

---

## 12. Qo'shimcha resurslar

* [Wazuh Documentation](https://documentation.wazuh.com/)
* [Wazuh Kibana App](https://documentation.wazuh.com/current/user-manual/kibana-app/index.html)
* Community forums va GitHub repository misollari

---

> Wazuh SIEM va endpoint security platformasi bo‘lib, log monitoring, threat detection va compliance reporting imkoniyatlarini kengaytiradi.
