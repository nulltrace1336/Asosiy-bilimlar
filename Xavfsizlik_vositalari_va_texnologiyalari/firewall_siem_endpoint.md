# Xavfsizlik Vositalari va Texnologiyalari Qo‘llanmasi

Ushbu qo‘llanma kiberxavfsizlik bo‘yicha ishlatiladigan asosiy vositalar va texnologiyalarni tushuntiradi.

---

## 🔸 Firewalldr & IDS/IPS

### Firewall va IDS/IPS nima?
- **Firewall** – tarmoq trafikini nazorat qilish va ruxsat berish yoki rad qilish.
- **IDS (Intrusion Detection System)** – tarmoqqa kirayotgan va chiqayotgan trafikni kuzatib, xavfsizlik tahdidlarini aniqlaydi.
- **IPS (Intrusion Prevention System)** – IDS funksiyasini bajaradi va tahdidlarni avtomatik to‘xtatadi.

### Mashhur tizimlar
| Tizim | Tavsif |
|-------|--------|
| **pfSense** | Open-source firewall va router. VPN, NAT, firewall qoidalari bilan ishlash. |
| **Cisco ASA** | Korporativ darajadagi firewall, VPN va IDS/IPS funksiyalari. |
| **Fortigate** | Integratsiyalashgan firewall va xavfsizlik platformasi, antivirus, web filtering, IPS bilan birga. |

### IDS/IPS vositalari
| Tizim | Tavsif |
|-------|--------|
| **Suricata** | Open-source IDS/IPS va tarmoq xavfsizligi monitoring vositasi. |
| **Snort** | Eng mashhur open-source IDS, real-time tarmoq trafik tahlili va paket tekshiruvi. |
| **Zeek** | (Oldingi Bro) tarmoq monitoring va log yaratish tizimi, anomaliyalarni aniqlashda kuchli. |

---

## 🔸 SIEM tizimlar

### SIEM nima?
**SIEM (Security Information and Event Management)** – xavfsizlik hodisalarini markazlashgan tarzda yig‘ish, tahlil qilish va ogohlantirish tizimi.

### Mashhur tizimlar
| Tizim | Tavsif |
|-------|--------|
| **Splunk** | Katta hajmdagi loglarni yig‘ish, qidirish, tahlil va vizualizatsiya qilish imkoniyati. |
| **ELK / Elastic SIEM** | Elasticsearch, Logstash, Kibana asosida loglarni yig‘ish va real-time tahlil qilish. |
| **Wazuh** | Open-source SIEM, log monitoring, konfiguratsiya nazorati, xavfsizlik tekshiruvi. |

### Amaliy ishlar
- Loglarni yig‘ish va indekslash
- Anomaliyalarni aniqlash
- Hodisalar bo‘yicha alertlar yaratish

---

## 🔸 Endpoint Security

### Endpoint Security nima?
Tarmoqdagi individual qurilmalarni (kompyuter, server, mobil) himoya qiluvchi vositalar.

### Mashhur vositalar
| Tizim | Tavsif |
|-------|--------|
| **EDR (Endpoint Detection & Response)** | Tarmoq qurilmalardagi tahdidlarni aniqlash va javob choralarini avtomatlashtirish. |
| **Crowdstrike** | Bulut asosida EDR, real-time monitoring va tahdidlarni bloklash. |
| **SentinelOne** | AI asosida EDR, malware, ransomware va boshqa tahdidlarni bloklash. |
| **Defender ATP** | Microsoft Endpoint Security, Windows tizimlarini himoya qiladi. |
| **Antiviruslar** | Klasik himoya vositalari: malware va viruslarni aniqlash. |
| **Sandboxing** | Shubhali fayllarni izolyatsiya qilib ishlatish, zararli dastur xatti-harakatini tahlil qilish. |

### Amaliy ishlar
- Endpoint monitoringni yoqish
- EDR orqali hodisalarni kuzatish
- Sandboxing bilan fayllarni tekshirish

---

### Tavsiya
- IDS/IPS bilan firewalllarni integratsiya qilish
- SIEM orqali loglarni markazlashtirish va tahlil qilish
- Endpoint Security bilan foydalanuvchi qurilmalarini himoya qilish
