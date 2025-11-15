1 — Tez xulosa (nima qiladi va qachon ishlatish)

Suricata — ochiq manbali tarmoq IDS/IPS va paket tahlil dvigateli (network security monitoring). U:

trafikni dekodlaydi (HTTP/DNS/TLS va boshqalar),

qoidalar (ET/Snort) bilan hujumlarni aniqlaydi,

EVE JSON orqali boy log chiqaradi (alerts, http, dns, tls, files),

inline (IPS) yoki passive (IDS) rejimida ishlaydi. 
Suricata Documentation
+1

2 — O‘rnatish (tezkor, Ubuntu/Debian misol)

Paket manbadan yoki source-dan o‘rnatish mumkin; rasmiy paketlar va build qo‘llanmasi mavjud. (rivojlangan tizimlar uchun source tavsiya qilinadi). 
Suricata Documentation

Ubuntu/Debian (paketlar misol):
```bash
sudo apt update
sudo apt install -y suricata
# yoki rasmiy repo va versiyani tekshirish uchun docsga qarang
suricata --build-info
```

Source’dan o‘rnatish kerak bo‘lsa rasmiy qo‘llanmani kuzating (./configure, make, make install). 
Suricata Documentation

3 — Birinchi ishga tushirish (passive IDS)

suricata.yaml asosiy konfiguratsiya fayli — /etc/suricata/suricata.yaml.

Minimal ishga tushirish (misol: interface eth0):
```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

eve.json ni yoqish uchun suricata.yaml ichidagi eve-log bo‘limini tekshiring (enabled: yes) — EVE JSON Suricata loglarini markaziy SIEM/ELK ga jo‘natishda ishlatiladi. 
Suricata Documentation
+1

4 — Qoidalar (rules) boshqaruvi: suricata-update

suricata-update — rasmiy rules updater. Defaultda Emerging Threats (ET Open) ishlatiladi va suricata-update bilan ruleslarni yuklaysiz/filtrlaysiz. Misol:
```bash
# oddiy yangilash
sudo suricata-update

# rules papkasini qayta yuklash va suricata restart
sudo systemctl restart suricata
```

/etc/suricata/ ichida enable.conf, disable.conf, drop.conf kabi filter fayllar bilan avtomatik modifikatsiya qilsa bo‘ladi. 
suricata-update.readthedocs.io

5 — IDS vs IPS — qanday va qaysi rejimlarda ishlatish

IDS (monitoring): SPAN/TAP orqali trafikni tinglaydi; no-risk (tarmoq kesilmaydi).

IPS (inline/prevention): paket oqimida joylashib trafikni to‘xtatadi yoki o‘zgartiradi (drop, reject). IPS uchun Suricata bir nechta usullarga ega: AF_PACKET (tap/ips mode), NFQ/NFQUEUE (netfilter), PF_RING yoki DPDK (yuqori trafik uchun).

AF_PACKET — L2/L3 inline va tap rejimida qulay (Linuxda keng qo‘llanadi; ikki interface talab qilinishi mumkin) — copy-mode: ips|tap. 
Suricata Documentation
+1

Misol: AF_PACKET konfiguratsiyasi (suricata.yaml ichidan, soddalashtirilgan):
```bash
af-packet:
  - interface: eth1
    threads: auto
    defrag: yes
    cluster-id: 99
    cluster-type: cluster_flow
    copy-mode: ips  # yoki tap
    use-mmap: yes
    tpacket-v3: yes
```

AF_PACKET IPS mode uchun odatda interface juftligi (in/out) kerak emas — Suricata paketlarni nusxalab va qaytaradi; docsga qarang. 
Suricata Documentation

6 — Suricata konfiguratsiyasida eng muhim bo‘limlar

af-packet / nfqueue / pfring / dpdk — capture method; qaror qiling (OS va hardware ga qarab). 
Suricata Documentation
+1

runmodes / threads — detect, decode, capture, output kabi thread turlarini boshqarish; corelar bo‘yicha ratio belgilash mumkin. Ko‘pincha detect uchun threads auto yoki cpu_count ga mos qilib sozlanadi. 
Suricata Documentation

detect-engine — Qoida optimization, thresholding, flow timeout va bilvosita qoidalarni boshqarish.

eve-log — EVE JSON format (alerts, http, dns, tls, files, flow). ELK/Filebeat integratsiyasi uchun asosiy manba. 
Suricata Documentation
+1

7 — Loglash va SIEM integratsiyasi

eve.json — barcha hodisalarni JSON ga chiqaradi; uni Filebeat, Logstash yoki fluentd orqali ELK/Elastic, Splunk yoki Graylog ga yuborasiz. DigitalOcean va Elastic dokumentlari Suricata+ELK integratsiya misollarini beradi. 
digitalocean.com
+1

Filebeat misol:
```bash
# filebeat.yml
filebeat.inputs:
- type: log
  paths:
    - /var/log/suricata/eve.json

# Suricata module ni yoqib, elasticsearchga yuborasiz
```
8 — Performance tuning (amaliy tavsiyalar)

Muhim: Suricata multi-threaded — to‘g‘ri capture method + CPU affinity + IRQ balancing + NIC offload sozlamalari zarur.

Asosiy punktlar:

AF_PACKET TPacket v3 + use-mmap — yuqori throughput. (tpacket-v3 va use-mmap ni yoqing). 
weizn.net

Disable NIC checksum offload agar kernel/driver paketlarni noto‘g‘ri ko‘rsatayotgan bo‘lsa (yoki capture.checksum-validation sozlash).

Qoida tuning — juda umumiy yoki juda ko‘p qoidalarni faollashtirmang; riskli qoidalarni drop ro‘yxatiga qo‘ying.

CPU pinning / irqbalance — Suricata threadlarini va NIC IRQlarni mos corelarga bog‘lang.

PF_RING / DPDK — 10Gb+ kabi linklar uchun akseleratorlar (agar mavjud bo‘lsa). 
Suricata
+1

Suricata runmodes va threading haqidagi rasmiy izohlar uchun docsga qarang. 
Suricata Documentation

9 — Test va validatsiya (traffic replay)

tcpreplay yordamida pcap faylni qayta uzatib Suricata qoidalarining ishlashini sinab ko‘ring:
```bash
sudo tcpreplay -i eth0 sample.pcap
```

scapy yoki har qanday pen-test trafiklarini yuborib alert olinayotganini tekshiring.

suricata -r sample.pcap -c /etc/suricata/suricata.yaml bilan pcapdan to‘g‘ridan-to‘g‘ri o‘qib tahlil qilish mumkin.

10 — Amaliy misollar (qisqa snippets)

a) Suricata ishga tushirish interface bilan (daemon systemd):
```bash
sudo systemctl enable --now suricata
# yoki debug rejimida
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```

b) Custom qoidani qo‘shish (ET/Snort sintaksisi):
/etc/suricata/rules/local.rules:
```bash
alert http any any -> any any (msg:"TEST HTTP admin login probe"; http.uri; content:"/admin/login"; nocase; sid:1000001; rev:1;)
```

so‘ng:
```bash
sudo suricata-update
sudo systemctl restart suricata
```

c) EVE JSON qismini yoqish (suricata.yaml ichida):
```bash
eve-log:
  enabled: yes
  filetype: regular
  filename: /var/log/suricata/eve.json
  types:
    - alert:
        tagged-packets: yes
    - http
    - dns
    - tls
    - files
    - flow
```

(so‘ng Filebeat bilan to‘g‘ri indekslashni qo‘shing). 
Suricata Documentation
+1

11 — Common muammolar va yechimlar

Ko‘p false-positive → qoidalarni whitelisting (disable.conf, modify.conf) va thresholding bilan kamaytiring.

Performance past → AF_PACKET/TPACKET v3, core pinning, disable offload, yoki PF_RING/DPDK ga o‘tish. 
Suricata
+1

EVE JSON juda katta → log rotatsiyasi va offload (filebeat) bilan boshqarish; filterlash (faqat kerakli types) yordam beradi. 
Suricata Documentation

12 — Qo‘shimcha resurslar (o‘qish uchun)

Suricata rasmiy docs — install, IPS setup, AF_PACKET, runmodes. 
Suricata Documentation
+1

EVE JSON haqida rasmiy sahifa (keng qamrovli log turlari). 
Suricata Documentation

suricata-update quickstart (rules manager). 
suricata-update.readthedocs.io

Performance tuning va PF_RING/DPDK misollari ham rasmiy va community forumlarda (suricata forum, bloglar). 
Suricata
+1

Suricata + ELK tutorial (DigitalOcean / Elastic community)







































# Suricata — To'liq amaliy qoʻllanma (IDS/IPS)

> Ushbu hujjat Suricata ni **oʻrnatish, sozlash, IDS vs IPS rejimlari, qoidalar boshqaruvi, loglash, performance tuning** va amaliy misollarni bosqichma-bosqich tushuntiradi. Misollar Linux (Ubuntu/Debian/RHEL) uchun moslashtirilgan.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Ubuntu/Debian misol)
4. Birinchi ishga tushirish (passive IDS)
5. Qoidalar (rules) boshqaruvi: `suricata-update`
6. IDS vs IPS — rejimlar va usullar
7. Muhim konfiguratsiya bo'limlari (`suricata.yaml`)
8. EVE JSON va SIEM integratsiyasi
9. Performance tuning (amaliy tavsiyalar)
10. Test va validatsiya (traffic replay)
11. Amaliy misollar (qoidalar, run, AF_PACKET)
12. Common muammolar va yechimlar
13. Qo'shimcha resurslar
14. Keyingi amaliy qadamlar

---

## 1. Tez xulosa

Suricata — ochiq manbali tarmoq IDS/IPS dvigateli. U:

* trafikni decode qiladi (HTTP, DNS, TLS va h.k.)
* ET/Snort qoidalari bilan hujumlarni aniqlaydi
* EVE JSON orqali boy log chiqaradi (alerts, http, dns, tls, files)
* monitoring (IDS) yoki inline (IPS) rejimida ishlaydi

---

## 2. Kerakli talablar

* Linux distributsiyasi (Ubuntu/Debian yoki RHEL/CentOS)
* Katta tarmoqda: *ko‘p CPU yadro*, tezkor SSD, 1G/10G NIClar
* Agar yuqori yuk: PF_RING yoki DPDK akseleratsiyasi, tpacket-v3 uchun kernel qo‘llab-quvvatlash

---

## 3. Oʻrnatish (Ubuntu/Debian misol)

Paketlardan yoki manba (source) dan o‘rnatish mumkin. Rasmiy docsga qarab versiyani tanlang.

```bash
sudo apt update
sudo apt install -y suricata
# suricata versiyasini tekshirish
suricata --build-info
```

Agar maxsus xususiyatlar kerak bo‘lsa (PF_RING, DPDK), source dan compile qilish tavsiya etiladi.

---

## 4. Birinchi ishga tushirish (passive IDS)

`suricata.yaml` asosiy konfiguratsiya fayli joylashgan: `/etc/suricata/suricata.yaml`.

Interfeysga bog‘lab ishga tushirish:

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

EVE JSON loglarini yoqish uchun `suricata.yaml` ichidagi `eve-log` bo‘limini tekshiring (enabled: yes).

---

## 5. Qoidalar (rules) boshqaruvi: `suricata-update`

`suricata-update` — rasmiy rules updater, Emerging Threats (ET Open) kabi manbalardan qoidalarni yuklaydi va filtrlash imkonini beradi.

Oddiy yangilash va suricata restart:

```bash
sudo suricata-update
sudo systemctl restart suricata
```

`suricata-update` bilan `enable.conf`, `disable.conf` yoki `drop.conf` kabi fayllar orqali qoidalarni boshqarish mumkin.

---

## 6. IDS vs IPS — rejimlar va usullar

* **IDS (monitoring):** SPAN/TAP orqali trafikni tinglash; xavfsiz (tarmoq kesilmaydi).
* **IPS (inline/prevention):** paket oqimida joylashib trafikni bloklaydi yoki o‘zgartiradi.

Suricata uchun mashhur capture methodlar:

* `af-packet` (Linux AF_PACKET, tpacket-v3) — yaxshi umumiy yechim; `copy-mode: tap` yoki `ips`.
* `nfqueue` (netfilter NFQUEUE) — iptables bilan integratsiya qilib packetlarni NFQ ga yuborish.
* `pfring` / `dpdk` — yuqori throughput talab qiladigan muhitlar uchun akseleratsiya.

### AF_PACKET (misol):

`suricata.yaml` ichiga soddalashtirilgan blok:

```yaml
af-packet:
  - interface: eth1
    threads: auto
    defrag: yes
    cluster-id: 99
    cluster-type: cluster_flow
    copy-mode: ips  # yoki tap
    use-mmap: yes
    tpacket-v3: yes
```

---

## 7. Muhim konfiguratsiya bo'limlari (`suricata.yaml`)

* **af-packet / nfqueue / pfring / dpdk** — capture usuli
* **runmodes / threads** — detect, decode, output uchun thread sozlamalari
* **detect-engine** — qoidalar optimallashtirish va thresholding
* **eve-log** — EVE JSON formatni yoqish va turlarini belgilash

EVE JSON misol konfiguratsiyasi:

```yaml
eve-log:
  enabled: yes
  filetype: regular
  filename: /var/log/suricata/eve.json
  types:
    - alert:
        tagged-packets: yes
    - http
    - dns
    - tls
    - files
    - flow
```

---

## 8. EVE JSON va SIEM integratsiyasi

* `eve.json` Suricata ning asosiy log manbai: alerts, http, dns, tls, files, flow.
* Filebeat yoki Logstash orqali `eve.json` ni ELK/Elastic, Splunk yoki Graylog ga yuboring.

Filebeat misol (keng ko‘lamli):

```yaml
filebeat.inputs:
- type: log
  paths:
    - /var/log/suricata/eve.json

filebeat.modules:
# Suricata module mavjud bo'lsa uni yoqing
```

---

## 9. Performance tuning (amaliy tavsiyalar)

Suricata multi-threaded — to‘g‘ri capture method + CPU affinity + IRQ balancing + NIC offload sozlamalari zarur.

Asosiy punktlar:

1. **AF_PACKET + tpacket-v3 + use-mmap** — yuqori throughput uchun.
2. **NIC offload** — kernel/driver paketlarni noto‘g‘ri ko‘rsatmasa, offloadni o‘chiring yoki `capture.checksum-validation` sozlang.
3. **Qoida tuning** — juda umumiy qoidalar va ko‘p qoidalarni faollashtirmang.
4. **CPU pinning / irqbalance** — Suricata threadlarini va NIC IRQlarni mos corelarga bog‘lang.
5. **PF_RING / DPDK** — 10Gb+ linklar uchun akseleratorlarni ko‘rib chiqing.

Qo‘shimcha: Suricata runmodes va threading haqida rasmiy docsni tekshiring.

---

## 10. Test va validatsiya (traffic replay)

* `tcpreplay` yordamida pcap faylni qayta uzatib Suricata qoidalarini sinab ko‘ring:

```bash
sudo tcpreplay -i eth0 sample.pcap
```

* `suricata -r sample.pcap -c /etc/suricata/suricata.yaml` bilan pcapdan to‘g‘ridan-to‘g‘ri tahlil.
* `scapy` yoki pen-test trafiklarini yuborib alert olinayotganini tekshiring.

---

## 11. Amaliy misollar

### a) Suricata daemonni systemd orqali ishga tushirish:

```bash
sudo systemctl enable --now suricata
# yoki direct
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -v
```

### b) Local qoidani qo‘shish:

`/etc/suricata/rules/local.rules` fayliga:

```text
alert http any any -> any any (msg:"TEST HTTP admin login probe"; http.uri; content:"/admin/login"; nocase; sid:1000001; rev:1;)
```

so‘ng: `sudo suricata-update && sudo systemctl restart suricata`

### c) EVE JSON yoqish (suricata.yaml ichida) — yuqorida berilgan misolga qarang.

---

## 12. Common muammolar va yechimlar

* **Ko‘p false-positive** → qoidalarni whitelist (disable.conf / modify.conf), thresholding va tuning orqali kamaytiring.
* **Performance pasayishi** → AF_PACKET/TPACKET v3, core pinning, NIC offload sozlash yoki PF_RING/DPDK ga o‘tish.
* **EVE JSON juda katta** → faqat kerakli `types` ni yoqing va log rotatsiyasini tashkil qiling.

---

## 13. Qo'shimcha resurslar

* Suricata rasmiy hujjatlari (install, AF_PACKET, runmodes)
* suricata-update docs (qoidalar boshqaruvi)
* Suricata + ELK integratsiya misollari (Filebeat, Logstash)
* PF_RING/DPDK performance blog postlari va forumlar

---

## 14. Keyingi amaliy qadamlar — men nima yordam bera olaman

Agar xohlasangiz, men hozir quyidagilardan birini tayyorlab beraman:

1. **Home-lab uchun `suricata.yaml`** (AF_PACKET yoki IDS konfiguratsiyasi) — sizning interfeys nomlarini kiriting.
2. **Suricata + ELK (Filebeat/Logstash/Kibana) integratsiyasi** — step-by-step lab va Kibana dashboard misollari.
3. **IPS (AF_PACKET inline) toʻliq misoli** — AF_PACKET konfiguratsiyasi, kernel/iptables sozlash va test skriptlari.
4. **Performance tuning checklist** va `cpu_affinity` / irq pinning misollari — agar apparat (CPU, NIC modeli) ma’lum bo‘lsa maxsus tavsiyalar.

---

> Agar tayyorlangan markdown formatini `.md` fayl sifatida yuklab olishni xohlasangiz yoki unga qo‘shimchalar (misollar, diagramma, Kibana dashboard) qo‘shilishini istasangiz, ayting — men hozircha shu hujjatni yangilab bera olaman.
