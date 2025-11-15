# Snort — To'liq amaliy qoʻllanma (IDS/IPS)

> Ushbu hujjat Snort ni **oʻrnatish, sozlash, IDS/IPS rejimlari, qoidalar boshqaruvi, loglash, performans tuning** va amaliy misollarni bosqichma-bosqich tushuntiradi. Misollar Linux (Ubuntu/Debian/RHEL) uchun moslashtirilgan.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Ubuntu/Debian misol)
4. Birinchi ishga tushirish (passive IDS)
5. Qoidalar (rules) boshqaruvi
6. IDS vs IPS — rejimlar va usullar
7. Muhim konfiguratsiya fayllari (`snort.conf`)
8. Loglash va SIEM integratsiyasi
9. Performance tuning (amaliy tavsiyalar)
10. Test va validatsiya (traffic replay)
11. Amaliy misollar (qoidalar, run)
12. Common muammolar va yechimlar
13. Qo'shimcha resurslar
14. Keyingi amaliy qadamlar

---

## 1. Tez xulosa

Snort — ochiq manbali tarmoq IDS/IPS dvigateli. U:

* trafikni analiz qiladi (TCP/IP paketlarni decode qiladi)
* Snort qoidalari bilan hujumlarni aniqlaydi
* Unified2 va syslog formatida log chiqaradi
* Monitoring (IDS) yoki inline (IPS) rejimida ishlaydi

---

## 2. Kerakli talablar

* Linux distributsiyasi (Ubuntu/Debian yoki RHEL/CentOS)
* Tarmoqda yuqori yirik trafik uchun: *ko‘p CPU yadro*, tezkor SSD, 1G/10G NIClar
* Agar yuqori yuk: DAQ (Data Acquisition Library) versiyasi va kernel support kerak

---

## 3. Oʻrnatish (Ubuntu/Debian misol)

Paketlar va manbadan o‘rnatish mumkin. DAQ library va rasmiy docs tavsiya etiladi.

```bash
sudo apt update
sudo apt install -y snort snort-rules-default
snort -V  # versiya tekshirish
```

Agar DPDK yoki PF_RING qo‘llab-quvvatlash kerak bo‘lsa, source dan compile qilish tavsiya qilinadi.

---

## 4. Birinchi ishga tushirish (passive IDS)

`snort.conf` asosiy konfiguratsiya fayli joylashgan: `/etc/snort/snort.conf`

Interfeysga bog‘lab ishga tushirish:

```bash
sudo snort -c /etc/snort/snort.conf -i eth0 -A console
```

* `-A console` — alertlarni terminalga chiqaradi
* `-i eth0` — traffic tinglanadigan interfeys

---

## 5. Qoidalar boshqaruvi

* Snort qoidalari `/etc/snort/rules/` papkada joylashgan
* Emerging Threats (ET) yoki community qoidalar bilan kengaytirish mumkin
* Qoidalarni yangilash uchun `pulledpork` yoki rasmiy update scriptlar ishlatiladi

Misol: ET Open rules update

```bash
pulledpork.pl -c /etc/snort/pulledpork.conf -u
sudo systemctl restart snort
```

---

## 6. IDS vs IPS — rejimlar va usullar

* **IDS (monitoring):** SPAN/TAP orqali trafikni tinglaydi, xavfsiz
* **IPS (inline/prevention):** paket oqimida joylashib trafikni bloklaydi

Snort IPS uchun DAQ driver yordamida inline mode ishlatiladi. Misol:

```bash
snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf -i eth0
```

* `-Q` — IPS inline mode
* `--daq nfq` — NFQUEUE orqali paketni qabul qilish

---

## 7. Muhim konfiguratsiya fayllari (`snort.conf`)

* `var HOME_NET` — ichki tarmoq manzillari
* `var EXTERNAL_NET` — tashqi tarmoq manzillari (`any` yoki `!$HOME_NET`)
* `include $RULE_PATH/local.rules` — local qoidalarni qo‘shish
* Preprocessors — trafikni decode va normalize qilish uchun

---

## 8. Loglash va SIEM integratsiyasi

* Default log format: Unified2 (`/var/log/snort/`)
* Syslog yoki EVE JSON (Suricata bilan mos) orqali loglarni SIEM ga yuborish mumkin
* Log forward qilish uchun Filebeat yoki Logstash ishlatiladi

---

## 9. Performance tuning

* Multi-threaded IDS uchun `snort` 2.9+ versiyasi, PF_RING, DPDK yoki AF_PACKET bilan tezlatish
* Preprocessor va qoidalarni optimallashtirish
* NIC offload va CPU affinity sozlash

---

## 10. Test va validatsiya

* `tcpreplay` yordamida pcap faylni Snort orqali test qilish:

```bash
sudo snort -r sample.pcap -c /etc/snort/snort.conf
```

* Pen-test trafiklarini yuborib alert olinayotganini tekshirish

---

## 11. Amaliy misollar

### a) Snort daemon ishga tushirish

```bash
sudo systemctl enable --now snort
```

### b) Local qoidani qo‘shish

`/etc/snort/rules/local.rules`:

```text
alert tcp any any -> any 80 (msg:"TEST HTTP admin login probe"; content:"/admin/login"; nocase; sid:1000001; rev:1;)
```

so‘ng:

```bash
sudo systemctl restart snort
```

### c) Inline IPS misol (NFQUEUE)

```bash
snort -Q --daq nfq --daq-var queue=0 -c /etc/snort/snort.conf -i eth0
```

---

## 12. Common muammolar va yechimlar

* **Ko‘p false-positive** → qoidalarni whitelist va thresholding bilan kamaytiring
* **Performance pasayishi** → PF_RING/DPDK, CPU pinning, NIC offload
* **Loglar juda katta** → faqat kerakli log turlarini yoqing va rotatsiya qiling

---

## 13. Qo'shimcha resurslar

* [Snort rasmiy hujjatlari](https://snort.org/documents)
* PulledPork qoidalar boshqaruvi
* Snort + ELK integratsiya tutoriallari
* Performance tuning va PF_RING/DPDK misollari forum va bloglar

---

## 14. Keyingi amaliy qadamlar

1. Home-lab uchun `snort.conf` tayyorlash
2. Snort + ELK integratsiya lab va Kibana dashboard
3. IPS (NFQUEUE) to‘liq misoli
4. Performance tuning checklist (CPU, NIC, preprocessor optimizatsiyasi)
