Burp Suite - To'liq Qo'llanma
Burp Suite - bu veb-ilovalar xavfsizligini tekshirish uchun eng mashhur vosita. Keling, uni batafsil o'rganamiz.
1. Burp Suite Nima?
Burp Suite - penetration testing va veb-ilovalar xavfsizligini tekshirish uchun professional vosita. PortSwigger kompaniyasi tomonidan ishlab chiqilgan.
Versiyalari:

Community Edition - bepul, asosiy funksiyalar
Professional - to'liq funksional, pullik
Enterprise - korporativ, avtomatlashtirilgan skanerlash

2. O'rnatish va Sozlash
O'rnatish:

portswigger.net saytidan yuklab oling
Java kerak (odatda birga keladi)
O'rnatish va ishga tushirish

Brauzer Sozlash:
Firefox yoki Chrome uchun:

Proxy sozlamalarga kiring
Manual proxy configuration tanlang
HTTP Proxy: 127.0.0.1 Port: 8080
HTTPS uchun ham xuddi shunday

FoxyProxy kengaytmasini o'rnatish (tavsiya):

Bir klik bilan proxy yoqish/o'chirish imkoniyati

3. SSL Sertifikatini O'rnatish
HTTPS trafikni ko'rish uchun:

Burp Suite'ni ishga tushiring
Brauzerda http://burp ga kiring
"CA Certificate" tugmasini bosing va yuklab oling
Brauzerga sertifikat qo'shish:

Firefox: Settings → Privacy & Security → Certificates → View Certificates → Import
Chrome: Settings → Security → Manage certificates → Import



4. Asosiy Modullar
A) Proxy (Eng muhim modul)
Intercept tab:

HTTP/HTTPS so'rovlarni to'xtatib, tahrirlash
Intercept is on/off tugmasi bilan boshqarish
Forward - so'rovni jo'natish
Drop - so'rovni bekor qilish
Action - turli amallar

HTTP History:

Barcha so'rovlar tarixi
Filter sozlash mumkin
Har bir so'rovni batafsil ko'rish

WebSockets History:

WebSocket aloqalarini monitoring

B) Repeater
So'rovlarni qayta-qayta jo'natish uchun:

Proxy yoki boshqa joydan so'rovni Send to Repeater qiling
So'rovni tahrirlang
Send tugmasini bosing
Javobni tahlil qiling

Foydasi:

SQL Injection tekshirish
Parametrlarni o'zgartirish
Token va autentifikatsiyani test qilish

C) Intruder (Professional)
Avtomatik hujumlar uchun:
Hujum turlari:

Sniper - bitta parametrni ketma-ket test qilish
Battering ram - barcha pozitsiyalarga bir xil payload
Pitchfork - bir nechta parametrni parallel
Cluster bomb - barcha kombinatsiyalar

Qo'llash:

So'rovni Intruder'ga yuboring
Pozitsiyalarni belgilang (§payload§)
Payload turini tanlang (wordlist, numbers, etc.)
Attack boshlang

D) Scanner (Professional only)
Avtomatik zaifliklarni topish:

SQL Injection
XSS (Cross-Site Scripting)
CSRF
Path Traversal
va boshqalar

E) Decoder
Ma'lumotlarni kodlash/dekodlash:

Base64
URL encoding
HTML encoding
Hex
Hash (MD5, SHA-256, etc.)

F) Comparer
Ikki javob yoki so'rovni solishtirish:

Word level
Byte level
Farqlarni highlight qilish

G) Sequencer
Token va session ID randomligini tekshirish:

Session tokenlar kuchini baholash
Entropy tahlili

5. Amaliy Misollar
Misol 1: Login Bypass Tekshirish
1. Login formaga urinish qiling
2. Burp Proxy'da so'rovni to'xtating
3. Username va parolni tahrirlang:
   - username=admin' OR '1'='1
   - password=anything
4. Forward qiling
5. SQL Injection borligini tekshiring
Misol 2: Brute Force Attack
1. Login so'rovni Intruder'ga yuboring
2. Password maydonini §password§ qilib belgilang
3. Payloads → Load dan parol lug'atini yuklang
4. Attack boshlang
5. Status code 200 yoki Length farqini qidiring
Misol 3: Session Token Analizi
1. Target saytga bir necha marta login qiling
2. Session tokenlarni Sequencer'ga yuboring
3. Start live capture
4. Minimum 100-200 token to'plang
5. Analyze now - randomlik darajasini ko'ring
6. Pro Maslahatlar
Scope Sozlash:

Target tab → Scope
Faqat test qilmoqchi bo'lgan domenni qo'shing
Proxy → Options → Intercept Client Requests → "And URL is in target scope"

Filter Ishlatish:

Faqat kerakli so'rovlarni ko'rsatish
Extension (js, css, png) ni yashirish
Status code bo'yicha filterlash

Match and Replace:

Har bir so'rovda avtomatik o'zgartirish
Header qo'shish yoki o'chirish
User-Agent o'zgartirish

Session Handling Rules:

Avtomatik login
Token yangilash
Cookie boshqarish

7. Xavfsizlik va Etika
MUHIM ESLATMALAR:
⚠️ Faqat ruxsat berilgan saytlarni test qiling!

Sizning loyihalaringiz
Mijoz ruxsati bilan
Bug bounty platformalar (HackerOne, Bugcrowd)

❌ Qonuniy oqibatlar:

Ruxsatsiz penetration testing jinoyat
Uyda o'rganish uchun maxsus lab muhitlar yarating

✅ O'rganish uchun:

DVWA (Damn Vulnerable Web Application)
WebGoat
HackTheBox
TryHackMe
PortSwigger Web Security Academy

8. O'rganish Resurslari

PortSwigger Academy - bepul, professional treninglar
YouTube - praktik videolar
OWASP Top 10 - eng keng tarqalgan zaifliklar
Bug Bounty platformalar - real tajriba

Xulosa
Burp Suite juda kuchli vosita, lekin mas'uliyat bilan foydalanish kerak. Dastlab oddiy funksiyalarni o'rganing (Proxy, Repeater), keyin murakkabrog (Intruder, Scanner) ga o'ting.
