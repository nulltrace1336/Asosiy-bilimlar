IDS (Intrusion Detection System) — batafsil tushuntirish

Quyida IDS nima, qanday turlari bor, qanday ishlaydi, joylashtirish usullari, mashhur ochiq/kasbiy mahsulotlar, sozlash va yaxshilash bo‘yicha amaliy tavsiyalar — hammasi bir joyda, aniq va foydali.

1. IDS nima?

IDS — tarmoqqa yoki tizimga kiruvchi yoki undan chiqayotgan trafikni yoki xatti-harakatlarni tahlil qilib, mumkin bo‘lgan hujumlar/zaifliklardan xabar beruvchi tizim. IDS faqat ogohlantiradi (alert) — ko‘pincha bloklamaydi. IPS (Intrusion Prevention System) esa aktiv ravishda trafikni bloklashi mumkin.

2. IDS turlari

NIDS (Network-based IDS)

Tarmoq trafikini pasiv tarzda tahlil qiladi (masalan: Snort, Suricata, Zeek).

Switch SPAN port yoki network tap orqali trafikni oladi.

HIDS (Host-based IDS)

Bir server yoki endpointdagi faoliyatni kuzatadi: fayl tizimi o‘zgarishlari, jarayonlar, loglar. (masalan: OSSEC, Wazuh, Tripwire)

Hybrid / Distributed IDS

NIDS va HIDS komponentlari birlashtirilgan, ko‘p sensorli arxitektura.

Signature-based (imzo asosida)

Ma’lum hujum imzolari (pattern) bilan solishtiradi — aniq hujumlarni tez topadi, ammo nol-kun/unknown hujumlarni topmaydi.

Anomaly-based (norma buzilishiga asoslangan)

Normal xulqni o‘rganib, undan chetlangan holatlarni aniqlaydi — nol-kun hujumlarni topishi mumkin, ammo false positive ko‘proq bo‘ladi.

Hybrid

Ikkala yondashuvni ham ishlatadi.

3. IDS arxitekturasi va komponentlari

Sensor (sensor/probe) — trafik yoki host ma’lumotlarini yig‘adi va analiz qiladi.

Manager/Controller — sensorlarni boshqaradi, qoidalar va yangilanishlarni tarqatadi.

Console / UI — hodisalarni ko‘rsatish va tahlil qilish (dashboard).

Storage / Log collector — hodisalar va loglarni saqlaydi (odatda SIEM bilan integratsiya qilinadi).

Rule/Signature database — imzolar qatori (snort.rules, suricata rules).

Alerting/Notification — email, webhook, syslog va boshqalar orqali ogohlantirish yuboradi.

4. Joylashtirish (Deployment) usullari

Passive (monitoring) — SPAN/tap orqali trafikni tinglash; hech qanday bloklash yo‘q. Kamroq xavf, ishlab chiqish uchun yaxshi.

Inline (IPS) — trafikni real vaqtda tahlil qilib bloklaydi (IPS rejimi). Xatolik bo‘lsa xizmatga ta’sir qilishi mumkin.

Distributed sensors — turli segmentlarda bir nechta sensor; markaziy boshqaruv orqali yig‘adi.

Cloud/Host-based — cloud provayderdagi virtual sensorlar yoki host agentlar.

5. Mashhur ochiq manba va tijoriy yechimlar

(Ochiq: Snort, Suricata, Zeek, OSSEC, Wazuh. Tijoriy: Cisco Secure IPS, Palo Alto, Fortinet FortiGate IPS, McAfee, IBM QRadar IDS/IPS modullari.)

Eslatma: mahsulot tanlash sizning byudjet, tarmoq hajmi, ishlatish soddaligi va integratsiya ehtiyojlariga bog‘liq.

6. Misollar: Snort / Suricata qoidalari va Zeek

Snort qoidasi (oddiy TCP exploit alert):
```bash
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"WEB exploit attempt"; flow:to_server,established; content:"/admin/login"; nocase; sid:1000001; rev:1;)
```

Suricata qoidasi (yana shunga o‘xshash):
```bash
alert http any any -> any any (msg:"Possible admin login probing"; http.uri; content:"/admin/login"; nocase; sid:1000002; rev:1;)
```

Zeek script (oddiy HTTP loglash):
```bash
# http-log.zeek
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
    print fmt("%s %s %s -> %s", c$id$orig_h, method, unescaped_URI, c$id$resp_h);
}
```
7. Sozlash va tuning — amaliy tavsiyalar

Imzolarni yangilab boring — imzo bazasini va rules-ni muntazam yangilang.

Whitelist/ignore qoidalari — ichki, ma’lum oqil trafikni whitelistek (false positive kamayadi).

Baselining / normal profilni o‘rganish — anomaly-based tizimlar uchun normal xatti–harakatni o‘rganing.

Qoida optimallashtirish — kam samarali qoida yoki juda umumiy contentlarni aniqlab, o‘zgartiring.

Resurslar va performance — ko‘p trafik bo‘lsa, sensorlar CPU/IO va tarmoq kartalariga etibor bering (hardware offload, multi-threading Suricata).

Loglarni markazlashtirish — SIEM bilan integratsiya qilib, korrelyatsiya qiling (Wazuh, ELK, Splunk).

Alert prioritetlash — yuqori xavfli hodisalar uchun yuqori prioritet belgilang va avtomatlashtirilgan javoblarni (playbook) tayyorlang.

Regulyar review — haftalik/oylik false positive tahlili va rule yangilash.

Incident response integratsiyasi — IDS ogohlantirishdan keyingi jarayon (kuzatuv, izolyatsiya, forensika) aniq bo‘lsin.

Test va simulation — Red team/pen-testing orqali qanchalik aniqlayotganini sinab ko‘ring.

8. IDS ni aylanib o‘tish (evasion) usullari — nimaga e’tibor berish kerak

Trafikni shifrlash (TLS) — NIDS uchun to‘liq tahlil qiyin; TLS terminatsiyasi yoki host-based monitoring kerak.

Fragmentatsiya va paket soxta qilish — sensorlar fragmentlarni qayta yig‘ishi kerak.

Polymorphic malware va obfuscation — signature detection kamayadi.

Timing (low-and-slow) hujumlar — anomaly detection yordam beradi, ammo sozlash talab etiladi.

9. Me’moriy va amaliy checklist (tezyordamli)

 NIDS yoki HIDS? (yoki ikkalasi)

 Sensorlar qayerga joylashtiriladi (edge, core, DMZ)?

 SPAN/tap yoki inline?

 Imzo va anomaly rejimini qanday aralashtirish?

 Loglarni qayerga yuborasiz (SIEM)?

 Alertlarni kim ko‘radi va qanday response playbook bor?

 Qoida boshqaruvi va yangilanish jarayoni belgilanganmi?

 False positive kamaytirish siyosati bor?

 Resurs monitoring (CPU, memory, packet loss) o‘rnatilganmi?

10. Amaliy tavsiya: qayerdan boshlash?

Kichik tarmoqqa: Suricata yoki Zeek + ELK/Wazuh stack — ochiq va yaxshi hujjatlangan.

Endpoint uchun: Wazuh/OSSEC agentlarini kiriting.

Loglarni SIEM-ga yuboring va alertlarni avtomatlashtiring.

Haftalik false-positive review va oyiga bir marta imzo yangilash.