Nikto - Veb-server skaneri
Nikto - bu ochiq kodli veb-server zaifliklarini tekshirish uchun mo'ljallangan kuchli skaner. Keling, uni qanday ishlatishni batafsil ko'rib chiqamlik.
O'rnatish
Linux (Debian/Ubuntu):
bashsudo apt-get update
sudo apt-get install nikto
Kali Linux:
bash# Odatda oldindan o'rnatilgan
nikto -Version
Asosiy sintaksis
nikto -h <manzil> [opsiyalar]
Muhim parametrlar va misollar
1. Oddiy skanerlash
nikto -h http://example.com
nikto -h 192.168.1.100
2. SSL/HTTPS skanerlash
nikto -h https://example.com -ssl
3. Port ko'rsatish
nikto -h example.com -p 8080
nikto -h example.com -p 80,443,8080
4. Natijalarni saqlash
bash# HTML formatda
nikto -h example.com -o natija.html -Format html

# CSV formatda
nikto -h example.com -o natija.csv -Format csv

# Tekst formatda
nikto -h example.com -o natija.txt -Format txt
5. Ma'lum bir turdagi testlarni bajarish
bash# Faqat CGI zaifliklarini tekshirish
nikto -h example.com -Tuning 1

# Server konfiguratsiya xatoliklarini tekshirish
nikto -h example.com -Tuning 2

# Ma'lumotlar bazasi zaifliklarini tekshirish
nikto -h example.com -Tuning 3
6. User-Agent o'zgartirish
nikto -h example.com -useragent "Mozilla/5.0"
7. Autentifikatsiya bilan ishlash
nikto -h example.com -id username:password
8. Maxsus so'rovlar soni
bash# Sekinroq skanerlash (IDS/IPS ni chetlab o'tish uchun)
nikto -h example.com -Pause 5
Tuning opsiyalari

0 - Fayl yuklash
1 - Qiziqarli fayl/Ko'rinadigan fayl
2 - Noto'g'ri konfiguratsiya/Default fayl
3 - Ma'lumotlar uchun so'rovlar
4 - XSS/Skript/HTML ineksiyasi
5 - Remote fayl qidiruv (RFI)
6 - Denial of Service
7 - Remote fayl kiritish
8 - Buyruq bajarish
9 - SQL ineksiyasi
a - Autentifikatsiya chetlab o'tish
b - Dasturiy ta'minot versiyasini aniqlash
c - Ma'lumot sizib chiqishi
x - Reverse Tuning opsiyalari

Amaliy misollar
Keng qamrovli skanerlash
nikto -h example.com -ssl -p 443 -Format html -o natija.html -Tuning 123456789abc
Bir nechta hostlarni skanerlash
bash# hosts.txt faylida manzillar ro'yxati
nikto -h hosts.txt
Proksi orqali skanerlash
nikto -h example.com -useproxy http://proxy:8080
Vaqtni cheklash
nikto -h example.com -maxtime 30m
Foydali maslahatlar

Ruxsat olish: Faqat o'zingizga tegishli yoki ruxsat olingan serverlarda foydalaning
Sekinlashtirish: -Pause parametri bilan IDS/IPS tizimlarini chetlab o'tish mumkin
Natijalarni tahlil: HTML formatdagi natijalar eng qulay
Yangilanish: nikto -update bilan ma'lumotlar bazasini yangilang

Cheklovlar

Nikto shovqinli skanerdir (ko'p so'rovlar yuboradi)
IDS/IPS tizimlar tomonidan aniqlashi oson
False positive natijalar bo'lishi mumkin
Faqat ma'lum zaifliklarni topadi