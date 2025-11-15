# Vulnerable and Outdated Components

**Vulnerable and Outdated Components** (Zaif va eskirgan komponentlar) – bu dastur yoki tizim ichidagi kutubxonalar, ramkalar (frameworks), modul va boshqa komponentlarning eskirgan yoki xavfsizlik nuqtai nazaridan zaif bo‘lishi holatini anglatadi. Bunday komponentlar hujum qiluvchilar uchun kirish eshigini ochishi mumkin.

---

## 1. Tavsifi

- Dasturiy ta’minot tez-tez yangilanadi va eskirgan komponentlar xavfsizlik nuqtai nazaridan risk yaratadi.
- Ushbu komponentlar orqali **Remote Code Execution (RCE)**, **SQL Injection**, **Cross-Site Scripting (XSS)** va boshqa hujumlar amalga oshirilishi mumkin.
- Masalan, eskirgan **JavaScript kutubxonasi**, **CMS plaginlari**, **operatsion tizim paketlari** yoki **server komponentlari** bu toifaga kiradi.

---

## 2. Zaif komponentlarni aniqlash

### 2.1. Auditing va scanning
- **Software Composition Analysis (SCA) tools**: 
  - **OWASP Dependency-Check**
  - **Snyk**
  - **WhiteSource**
- **Manual review**:
  - Dasturiy komponentlar va ularning versiyalarini tekshirish.
  - Rasmiy release va security advisorylarni solishtirish.

### 2.2. Versiya monitoringi
- Paket menejerlar orqali o‘rnatilgan kutubxonalar versiyasini tekshirish:
  ```bash
  npm outdated      # Node.js
  pip list --outdated # Python
  gem outdated      # Ruby
Operatsion tizim paketlari uchun:

bash
Copy code
apt list --upgradable   # Debian/Ubuntu
yum check-update        # CentOS/RedHat
2.3. Vulnerability databases
NVD (National Vulnerability Database) – https://nvd.nist.gov

CVE Details – https://www.cvedetails.com

Vendor advisories (masalan, Apache, Microsoft, RedHat)

3. Chora ko‘rish
3.1. Yangilash
Eng oddiy va samarali chorasi – eskirgan komponentlarni eng so‘nggi xavfsiz versiyaga yangilash.

Automatic updates mumkin bo‘lgan komponentlarda avtomatik yangilashni yoqish.

3.2. Deprecation monitoring
Komponent ishlab chiqaruvchisi eskirganligini e’lon qilganida, iloji boricha tezroq muqobilini ishlatish.

3.3. Risk minimizatsiyasi
Agar darhol yangilash mumkin bo‘lmasa:

Zaif komponentning funksiyasini cheklash.

Input/Outputlarni tekshirish va sanitizatsiya qilish.

Firewall va WAF orqali filtrlar qo‘llash.

3.4. Continuous monitoring
CI/CD jarayoniga SCA scanning qo‘shish.

Kod va kutubxonalarni muntazam audit qilish.

4. Misollar
Komponent turi	Xavf	Chora ko‘rish
jQuery 1.11.0	XSS, RCE	Eng so‘nggi 3.x versiyaga yangilash
OpenSSL 1.0.1	Heartbleed, RCE	1.1.1 yoki 3.x yangilash
WordPress plugin eski	SQL Injection, XSS	Pluginni yangilash yoki o‘chirish
Python paket eski	Arbitrary Code Execution	pip install --upgrade bilan yangilash

5. Yakuniy tavsiyalar
Har doim komponent inventarizatsiyasini saqlash.

Security advisories va CVElarni kuzatish.

CI/CD pipeline’ga automated vulnerability scanning qo‘shish.

Minimal zaruriy paketlardan foydalanish va eskirganlarini tezda yangilash.

Manbalar:

OWASP: Using Components with Known Vulnerabilities

NVD - National Vulnerability Database

Snyk Blog - Dependency Management