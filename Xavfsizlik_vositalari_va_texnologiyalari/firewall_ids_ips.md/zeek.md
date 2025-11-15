# Zeek (Bro) — To'liq tahlil va qoʻllanma

> Ushbu hujjat Zeek (oldingi nomi Bro) ni **o‘rnatish, tahlil, skriptlar, loglash, SIEM integratsiyasi va amaliy misollar** bilan bosqichma-bosqich tushuntiradi. Misollar Linux (Ubuntu/Debian) uchun moslashtirilgan.

---

## Tarkib

1. Tez xulosa
2. Kerakli talablar
3. Oʻrnatish (Ubuntu/Debian misol)
4. Birinchi ishga tushirish
5. Zeek skriptlar va tahlil imkoniyatlari
6. Loglash va SIEM integratsiyasi
7. Performance tuning
8. Test va validatsiya
9. Amaliy misollar
10. Common muammolar va yechimlar
11. Qo'shimcha resurslar

---

## 1. Tez xulosa

Zeek — ochiq manbali tarmoq monitoring va security tahlil platformasi. U:

* Trafikni pasaytirmasdan analiz qiladi
* Real-time trafikni tahlil va eventlar yaratadi
* Skriptlar orqali custom detections va loglar yaratish mumkin
* SIEM va log serverlar bilan integratsiyalashadi

---

## 2. Kerakli talablar

* Linux distributsiyasi (Ubuntu/Debian yoki RHEL/CentOS)
* 1G/10G NIC, ko‘p CPU yadro va RAM tahlil uchun
* Python va scripting uchun optional paketlar

---

## 3. Oʻrnatish (Ubuntu/Debian misol)

Rasmiy Zeek repository yoki source dan o‘rnatish mumkin:

```bash
sudo apt update
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev zlib1g-dev

# Source dan o'rnatish
wget https://download.zeek.org/zeek-5.1.0.tar.gz
tar -xvzf zeek-5.1.0.tar.gz
cd zeek-5.1.0
./configure --prefix=/opt/zeek
make
sudo make install
```

Zeek versiyasini tekshirish:

```bash
/opt/zeek/bin/zeek --version
```

---

## 4. Birinchi ishga tushirish

Trafikni tinglash va monitoring:

```bash
sudo /opt/zeek/bin/zeek -i eth0
```

* `-i eth0` — trafik tinglanadigan interfeys
* Default loglar `logs/` papkada saqlanadi

---

## 5. Zeek skriptlar va tahlil imkoniyatlari

* Zeek skriptlar `.zeek` kengaytmasi bilan yoziladi
* Custom detection, alert, log yaratish uchun ishlatiladi
* Masalan, HTTP login event yaratish:

```zeek
@load base/protocols/http

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if ( original_URI == "/admin/login" ) {
        print fmt("Admin login request: %s", c$id$resp_h);
    }
}
```

* Skriptlar `scripts/` papkaga joylanadi va `zeekctl deploy` bilan ishga tushiriladi

---

## 6. Loglash va SIEM integratsiyasi

* Default loglar JSON formatida ham chiqarilishi mumkin
* Log turlari: `conn.log`, `http.log`, `dns.log`, `ssl.log`, `files.log`
* SIEM integratsiyasi uchun Filebeat, Logstash, Graylog yoki ELK ishlatiladi

Filebeat misol:

```yaml
filebeat.inputs:
- type: log
  paths:
    - /opt/zeek/logs/current/*.log
```

---

## 7. Performance tuning

* Multi-core CPU: Zeekworker yordamida load balancing
* Capture method: AF_PACKET, DPDK yoki PF_RING bilan tezlatish
* Log rotatsiyasi va compress qilish
* Only necessary scripts/analizlarni faollashtirish

---

## 8. Test va validatsiya

* `tcpreplay` bilan pcap faylni Zeek orqali o‘tkazish:

```bash
tcpreplay -i eth0 sample.pcap
```

* Log fayllarini tekshirish:

```bash
cat logs/current/conn.log
```

---

## 9. Amaliy misollar

### a) Zeek daemon ishga tushirish

```bash
sudo /opt/zeek/bin/zeek -i eth0
```

### b) Skript orqali alert yaratish

`scripts/custom_admin.zeek`:

```zeek
@load base/protocols/http

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    if ( original_URI == "/admin" ) {
        print fmt("Admin access attempt from: %s", c$id$resp_h);
    }
}
```

### c) Deploy custom script

```bash
zeekctl deploy
```

---

## 10. Common muammolar va yechimlar

* **Ko‘p false positive** → skriptlarni optimizatsiya qilish, faqat kerakli tahlillarni yoqish
* **Performance pasayishi** → multi-core workers, DPDK/AF_PACKET, log compress
* **Loglar juda katta** → JSON compress, rotate va archiving

---

## 11. Qo'shimcha resurslar

* [Zeek rasmiy sayt](https://zeek.org/)
* Zeek scripting guide
* Zeek + ELK integratsiya tutoriallari
* Zeek forum va GitHub repositorylar

---

> Zeek tarmoq monitoring va tahlil uchun juda mos platforma bo‘lib, yuqori trafik, real-time detection va log integratsiya imkoniyatlari
