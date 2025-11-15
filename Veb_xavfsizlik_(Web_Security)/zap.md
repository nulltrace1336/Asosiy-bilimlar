ZAP (Zed Attack Proxy) ishlatish bo'yicha batafsil qo'llanma
ZAP - bu veb-ilovalarning xavfsizligini tekshirish uchun bepul va ochiq kodli vosita. OWASP loyihasi tomonidan ishlab chiqilgan.
1. O'rnatish
Windows/Mac/Linux:

https://www.zaproxy.org/download/ saytidan yuklab oling
O'rnatuvchini ishga tushiring
Java 8+ talab qilinadi

2. Asosiy interfeys
ZAP ochilganda quyidagi asosiy qismlar ko'rinadi:

Tree tab - skanirlangan saytlar strukturasi
Sites tab - topilgan URL'lar
Request/Response - so'rov va javoblar
Alerts - topilgan zaifliklar

3. Asosiy ishlatish usullari
A) Manual Explore (Qo'lda tekshirish)
1. HUD ni yoqing: Launch Browser tugmasini bosing
2. Brauzer ochiladi va ZAP orqali trafik o'tadi
3. Saytni oddiy foydalanuvchidek ko'rib chiqing
4. ZAP avtomatik barcha so'rovlarni yozib boradi
B) Automated Scan (Avtomatik skan)
1. Automated Scan tugmasini bosing
2. Maqsadli URL kiriting: https://example.com
3. Attack tugmasini bosing
4. Natijalarni kuting
C) Manual Request (Qo'lda so'rov)
1. Manual Request Editor ni oching (Ctrl+M)
2. HTTP so'rovni yozing
3. Send tugmasini bosing
4. Asosiy funksiyalar
Spider (O'rgimchak)
Sayt strukturasini avtomatik o'rganadi:
Tools → Spider → URL kiriting → Start Scan
Active Scan
Zaifliklarni aktiv qidirib topadi:
Sites tabdan saytni tanlang → 
Right click → Attack → Active Scan
Passive Scan
Trafik o'tayotganda passiv tekshiradi (avtomatik ishlaydi)
Fuzzer
Kirish maydonlarini turli xil qiymatlar bilan sinash:
Request ni tanlang → Right click → 
Fuzz → Maydonni belgilang → Payloads qo'shing
5. Breakpoint ishlatish
HTTP so'rovlarni to'xtatib, o'zgartirish:
1. Set Break tugmasini yoqing
2. Saytga kirishda so'rov to'xtaydi
3. Request/Response ni tahrirlang
4. Submit tugmasini bosing
6. Scope (Qamrov) sozlash
Faqat kerakli saytlarni tekshirish:
Sites tabda → Right click → Include in Context →
Context nomi bering → OK
7. Authentication (Autentifikatsiya)
Login talab qiladigan saytlar uchun:
Tools → Options → Authentication →
Form-Based Authentication →
Login URL va credentials kiriting
8. Natijalarni ko'rish
Alerts Tab
Topilgan zaifliklar 4 darajada ko'rsatiladi:

🔴 High - Jiddiy zaifliklar
🟠 Medium - O'rtacha xavfli
🟡 Low - Past xavfli
🔵 Informational - Ma'lumot

Report yaratish
Report → Generate HTML Report →
Fayl nomini kiriting → Save
9. Foydali tugmalar

Ctrl+B - Breakpoint yoqish/o'chirish
Ctrl+M - Manual Request Editor
Ctrl+F - Qidirish
Ctrl+T - Yangi tab

10. Best Practices (Eng yaxshi amaliyotlar)

Scope sozlang - keraksiz saytlarni skanlamang
Authentication sozlang - login kerak bo'lsa
Passive → Spider → Active ketma-ketlikda ishlating
False Positive'larni tekshiring - hamma alert haqiqiy emas
Throttle sozlang - serverga yukni kamaytirish uchun

11. Umumiy zaifliklar
ZAP quyidagilarni topishi mumkin:

SQL Injection
XSS (Cross-Site Scripting)
CSRF tokenlari yo'qligi
Xavfli HTTP sarlavhalar
SSL/TLS muammolari
Cookie xavfsizligi
Va boshqalar...