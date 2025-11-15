🛡️ Threat Hunting Qo‘llanmasi
📌 Kirish

Threat Hunting — bu kiberxavfsizlik faoliyati bo‘lib, u avtomatlashtirilmagan va proaktiv tarzda tashkilot tarmoqlari va tizimlarida tahdidlarni aniqlashga qaratilgan.
Threat Hunting faqat alerts yoki signaturesga tayanmaydi; xavf-xatarlarni oldindan aniqlash, tahlil qilish va ularni yo‘q qilish maqsadida faol izlanishlarni o‘z ichiga oladi.

🔹 Threat Hunting Bosqichlari
1️⃣ Hypothesis (Faraz) Yaratish

Tahdidni izlashni boshlashdan oldin, faraz yaratiladi:

Masalan:

“Ichki foydalanuvchi ma’lumotlarni ruxsatsiz ko‘chirishi mumkin”

“Ransomware infektsiyasi tarmoqda tarqalmoqda”

Faraz business context va threat intelligence ma’lumotlariga asoslanadi.

2️⃣ Data Collection (Ma’lumot Yig‘ish)

Tahdidlarni aniqlash uchun turli manbalardan ma’lumot yig‘iladi:

## 🔹 Threat Hunting Manbalari

| Manba               | Maqsad                        | Asboblar / Usullar                     |
|--------------------|-------------------------------|---------------------------------------|
| Logs               | Foydalanuvchi va tizim faoliyati | SIEM (Splunk, ELK), Syslog           |
| Network Traffic    | Tarmoqdagi anomaliyalar       | Zeek, Wireshark, Suricata            |
| Endpoint           | Endpointdagi xatti-harakatlar | EDR (CrowdStrike, SentinelOne)       |
| Threat Intelligence| Tahdid indikatorlari          | VirusTotal, MISP, OpenCTI             |

3️⃣ Data Analysis (Ma’lumot Tahlili)

Anomaly Detection: normaldan chetga chiqishlarni aniqlash

Behavioral Analysis: foydalanuvchi yoki tizim xatti-harakatlarini tahlil qilish

Hunting Queries: SIEM yoki EDRda maxsus so‘rovlar yaratish

4️⃣ Investigation (Tergov)

Potensial tahdidlar aniqlangach, ularni chuqur tahlil qilish:

Logs correlatsiyasi

File hash va IOC tekshiruvi

Network flow va connection monitoring

5️⃣ Response (Javob Choralari)

Tahdid tasdiqlangach, uni yo‘q qilish yoki bloklash:

Endpoint isolation

Network segmentation

Account disable/block

Incident Response jamoasi bilan koordinatsiya

6️⃣ Documentation & Feedback

Topilgan tahdidlar va ularni bartaraf etish jarayoni dokumentatsiyalanadi.

Lessons Learned asosida hunting jarayoni optimallashtiriladi.

🔹 Hunting Methodologies

Indicator of Compromise (IOC) Based Hunting

Malum IOC (hash, IP, domain) bo‘yicha izlash.

Behavioral Hunting

Anomaliyalarni va g‘ayritabiiy xatti-harakatlarni tahlil qilish.

Hypothesis-Driven Hunting

Biznes konteksti va xavf intel ma’lumotlariga asoslangan farazlar.

Analytics-Driven Hunting

ML va AI yordamida anomal faoliyatlarni aniqlash.

🔹 Asboblar
Tur	Asboblar
## 🔹 Threat Hunting Asboblari

| Tur                | Asboblar                                      |
|-------------------|-----------------------------------------------|
| SIEM              | Splunk, ELK, QRadar                           |
| EDR               | CrowdStrike, SentinelOne, Microsoft Defender ATP |
| Network Monitoring | Zeek, Suricata, Wireshark                    |
| Threat Intel      | VirusTotal, MISP, OpenCTI                     |
| Automation        | Sigma Rules, MITRE ATT&CK, SOAR tools        |

🔹 MITRE ATT&CK Framework

Threat Hunting jarayonida MITRE ATT&CKdan foydalanish:

Techniques: Tashqi va ichki tahdidlarni aniqlash

TTPs: Adversary metodologiyasini tahlil qilish

Mapping: Detected anomaliyalarning ATT&CK teknikalariga mosligini tekshirish

🔹 Best Practices

Proaktiv bo‘ling: Alerts kutmang, faol qidiring.

Tarmoqlar va endpointlar bo‘yicha doimiy monitoring.

Hunting jarayonini dokumentatsiyalash va takomillashtirish.

Threat Intelligence bilan integratsiya.

SIEM va EDRda custom queries va dashboards yaratish.