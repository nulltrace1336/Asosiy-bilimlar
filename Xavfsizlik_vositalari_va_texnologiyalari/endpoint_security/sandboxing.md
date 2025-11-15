# Sandboxing — To'liq qoʻllanma

> Ushbu hujjat sandboxing texnologiyasi, uning ishlatilishi, konfiguratsiyasi, threat detection va amaliy misollar bilan bosqichma-bosqich tushuntiradi.

---

## Tarkib

1. Tez xulosa
2. Sandboxing tushunchasi
3. Sandboxing turlari
4. O‘rnatish va konfiguratsiya
5. Malware tahlili
6. Integration with EDR / SIEM
7. Performance va xavfsizlik
8. Amaliy misollar
9. Common muammolar va yechimlar
10. Qo'shimcha resurslar

---

## 1. Tez xulosa

Sandboxing — bu noaniq yoki zararli dasturlarni xavfsiz izolyatsiya qilingan muhitda ishga tushirib, ularning xatti-harakatini kuzatish jarayoni. U:

* Malware tahlili
* Threat detection
* Zero-day exploit monitoring
* Endpoint va network xavfsizligini oshiradi

---

## 2. Sandboxing tushunchasi

* Izolyatsiya: system va fayllardan alohida muhitda ishlaydi
* Monitoring: fayl, registry, tarmoq va process harakatlari kuzatiladi
* Logging: barcha faoliyatlar loglanadi, keyinchalik tahlil qilinadi
* Automated analysis: ML yoki signature-based detection bilan birga ishlaydi

---

## 3. Sandboxing turlari

* **Local sandbox**: Virtual Machine, Docker container, isolated OS
* **Cloud sandbox**: Palo Alto WildFire, FireEye, CrowdStrike Falcon Sandbox
* **Endpoint sandbox**: EDR integratsiyasi bilan (SentinelOne, Defender ATP)
* **Browser sandbox**: web-based exploits monitoring (Chrome, Edge isolated mode)

---

## 4. O‘rnatish va konfiguratsiya

### Local sandbox (VirtualBox/VMware)

```bash
# Ubuntu Linux VM yaratish
sudo apt update && sudo apt install virtualbox
# VM konfiguratsiyasi: 2GB RAM, 2 CPU, isolated network
```

### Cloud sandbox

* Palo Alto WildFire: cloud console orqali fayl submit va analysis
* CrowdStrike Falcon Sandbox: endpoint agent orqali malware file submit

---

## 5. Malware tahlili

* Fayl submit qilish sandboxga
* Process, file, registry va network monitoring
* Behavior logs export va tahlil
* Indicator of compromise (IOC) aniqlash

---

## 6. Integration with EDR / SIEM

* Sandboxing results SIEMga yuborish (Splunk, ELK, Wazuh)
* Automated alerts va dashboards
* Correlation with endpoint / network events

---

## 7. Performance va xavfsizlik

* VM yoki container resurs monitoring
* Snapshot/restore orqali tizim xavfsizligi
* Network isolation va firewall rules
* Logging va secure storage

---

## 8. Amaliy misollar

### a) Local sandbox malware analysis

```bash
# Linux VM ichida faylni ishga tushirish va process monitoring
./suspect_file &
top
```

### b) CrowdStrike Falcon Sandbox submit

* Falcon console → Sandbox → Submit file → Analysis results

### c) WildFire cloud submit

* File upload, wait for behavioral report, export IOC

---

## 9. Common muammolar va yechimlar

* **Malware VM dan chiqib ketishi** → snapshot restore, network isolation
* **Analysis kechikishi** → resource allocation, cloud sandbox parallelization
* **Logs yetarli emas** → enable verbose logging, monitor all process/events
* **False negatives** → multi-engine sandbox, combine ML & signature detection

---

## 10. Qo'shimcha resurslar

* [Palo Alto WildFire Documentation](https://www.paloaltonetworks.com/resources)
* [FireEye Malware Analysis](https://www.fireeye.com/services.html)
* [CrowdStrike Falcon Sandbox](https://www.crowdstrike.com/resources/)
* Security blogs va GitHub malware analysis labs

---

> Sandboxing zararli fayllarni xavfsiz izolyatsiya qilingan muhitda ishga tushirib, ularning xatti-harakatini kuzatish va threat detection jarayonini optimallashtirish imkonini beradi.
