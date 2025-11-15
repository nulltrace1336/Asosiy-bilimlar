Quyida Injection (OWASP Top 10 dagi eng muhim zaifliklardan biri) haqida batafsil, tushunarli va to‘liq markdown ko‘rinishida tayyor qo‘llanma beriladi.

🧨 Injection Zaifligi

Injection — bu foydalanuvchi kiritgan ma’lumotlar filtrlashsiz to‘g‘ridan‑to‘g‘ri backendga yuborilishi natijasida hujumchi serverga keraksiz buyruqlar, SQL kodlari, OS buyruqlari yoki boshqa scriptlar kiritib bajarishga majbur qila oladigan zaiflikdir.

U web‑ilovalarda eng ko‘p uchraydigan xatolardan biridir va katta xavfsizlik oqibatlariga olib keladi.

🚨 Injection turlari
1. SQL Injection (SQLi)

Eng mashhur tur. Hujumchi SQL so‘rovini manipulyatsiya qiladi.

Misol (zaif kod):
```bash
SELECT * FROM users WHERE username = '$user' AND password = '$pass';
```

Hujum misoli:
```bash
' OR '1'='1
```

Bu orqali hujumchi autentifikatsiyani chetlab o‘tadi.

2. OS Command Injection

Hujumchi serverda tizim buyruqlari bajarilishiga majbur qiladi.

Zaif kod:
```bash
system("ping " . $_GET['ip']);
```

Hujum misoli:
```bash
8.8.8.8; rm -rf /var/www
```
3. NoSQL Injection

MongoDB kabi NoSQL bazalaridagi zaifliklar.

Zaif so‘rov:
```bash
db.users.find({ "username": user, "password": pass });
```

Hujum misoli:
```bash
{"$ne": null}
```
4. LDAP Injection

LDAP kataloglariga noto‘g‘ri so‘rov yuborish.

Zaif kod:
```bash
(&(user=$user)(pass=$pass))
```

Hujum misoli:
```bash
*)(|(user=*))
```
5. XPath Injection

XML hujjatlariga soxta query yuborish orqali bypass qilish.

6. Email Header Injection

Email headerlariga qo‘shimcha buyruqlar yuborish.

🛑 Injectionning xavfli oqibatlari

🔥 Baza ma’lumotlarini o‘g‘irlash

🔥 Admin panelga kirib olish

🔥 Serverda buyruq bajarish

🔥 Ma’lumotlarni o‘chirish yoki o‘zgartirish

🔥 Tizimni butunlay egallab olish

🕵️ Injectionni qanday aniqlash?
✔ Burp Suite bilan test qilish

Repeater → kiritma maydonlarini manipulyatsiya qilish

Intruder → brute payload yuborish

Collaborator → Blind Injection tahlili

✔ Manually test

', ", ;, --, /* */, OR 1=1, ${7*7} kabi payloadlar

Response o‘zgarishlarini tahlil qilish

🔧 Injectionga qarshi himoya choralar
1. Parametrizatsiya (Prepared Statements) — Eng kuchli himoya

PHP PDO misol:
```bash
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$user, $pass]);
```

Python (PyMySQL):
```bash
cursor.execute("SELECT * FROM users WHERE user=%s AND pass=%s", (user, password))
```
2. ORM ishlatish

Django ORM, SQLAlchemy, Prisma, Eloquent — o‘z ichida himoya mexanizmlariga ega.

3. Input Validation

Faqat ruxsat berilgan ma’lumotlarni qabul qilish

Regex bilan tekshirish

Whitelist yondashuvi

4. Escaping

So‘rovga yuborilayotgan belgilarni tozalash.

5. WAF ishlatish

ModSecurity, NAXSI, Cloudflare WAF — zararli kiritmalarni bloklaydi.

🧪 Amaliy misollar
🔍 SQLi test
```bash
' OR 1=1 --
```
🔍 OS Injection test
```bash
8.8.8.8; whoami
```
🔍 NoSQL Injection test
```bash
{"$gt":""}
```
🎯 Xulosa

Injection — web‑ilovalardagi eng xavfli zaifliklardan biri. Ushbu zaiflikni oldini olish uchun:

Parametrizatsiya qiling

Foydalanuvchi kiritmalarini tozalang

ORM foydalaning

WAF qo‘shing

Penetratsion testlar o‘tkazing