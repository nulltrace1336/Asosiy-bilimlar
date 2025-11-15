TLS/SSL
📌 Kirish

TLS (Transport Layer Security) va SSL (Secure Sockets Layer) — bu internetdagi ma’lumotlarni shifrlash va xavfsiz uzatish protokollari. SSL – eski versiya, hozirgi va xavfsiz standarti TLS hisoblanadi.

Ularning asosiy maqsadi:

Ma’lumotlarni shifrlash orqali maxfiylikni ta’minlash

Ma’lumotlar yaxlitligini saqlash

Server va mijoz o‘rtasida autentifikatsiya (tasdiqlash)

🔑 Asosiy tushunchalar
Termin	Tavsif
Encryption (Shifrlash)	Ma’lumotlarni o‘qib bo‘lmaydigan holga keltirish
Authentication (Autentifikatsiya)	Server yoki mijozning haqiqiyligini tekshirish
Integrity (Yaxlitlik)	Ma’lumot uzatishda o‘zgarmaganligini ta’minlash
Handshake	TLS/SSL ulanishni boshlash jarayoni, kalitlar va shifrlash algoritmlari kelishib olinadi
⚡ Ishlash jarayoni (High-Level)

Client Hello – mijoz serverga TLS versiyasi va qo‘llab-quvvatlanadigan shifrlash algoritmlarini yuboradi

Server Hello – server TLS versiyasi va shifrlash algoritmini tanlaydi

Server Certificate – server sertifikatini yuboradi (haqiqiyligini CA orqali tekshiradi)

Key Exchange – server va mijoz sessiya kalitini almashadi

Session Keys Established – shifrlash va de-shifrlash uchun sessiya kaliti yaratiladi

Encrypted Communication – barcha keyingi ma’lumotlar shifrlangan tarzda uzatiladi

🔒 SSL vs TLS
Xususiyat	SSL	TLS
Versiyalar	SSL 2.0, 3.0	TLS 1.0, 1.1, 1.2, 1.3
Xavfsizlik	Zaif, eskirgan	Kuchli, zamonaviy
Ishlash	Handshake, MAC, shifrlash	Handshake, MAC, shifrlash, yaxshilangan algoritmlar
Hozirgi foydalanish	Amalda yo‘q	Standart, barcha brauzerlar va serverlar qo‘llaydi
🔑 Asosiy algoritmlar

Symmetric Encryption (Simmetrik shifrlash): AES, ChaCha20

Asymmetric Encryption (Asimmetrik shifrlash): RSA, ECDSA

Hash/Integrity: SHA256, SHA384

Key Exchange: Diffie-Hellman, ECDHE

🌐 Qo‘llanilishi

HTTPS (web saytlar)

Email serverlar (SMTP, IMAP, POP3)

VPN va boshqa tarmoq xizmatlari