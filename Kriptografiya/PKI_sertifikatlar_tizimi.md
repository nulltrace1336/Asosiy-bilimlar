PKI (Public Key Infrastructure) Sertifikatlar Tizimi
📌 Kirish

PKI (Public Key Infrastructure) – bu xavfsiz elektron aloqani ta’minlash uchun kriptografik kalitlar va sertifikatlarni boshqarish tizimidir. U asimmetrik shifrlashga asoslanadi va ma’lumotlarning shifrlanishi, autentifikatsiya va butunligini ta’minlaydi.

PKI asosiy maqsadlari:

Ma’lumotlarni shifrlash va maxfiyligini ta’minlash.

Foydalanuvchi yoki qurilmaning haqiqiyligini tasdiqlash (autentifikatsiya).

Ma’lumotlarning yaxlitligini tekshirish.

Raqamli imzo orqali ishonchlilikni ta’minlash.

🔑 Asosiy komponentlar
Komponent	Tavsif
CA (Certificate Authority)	Sertifikatlarni beruvchi tashkilot. U foydalanuvchi yoki serverning identifikatsiyasini tekshiradi va raqamli sertifikat beradi.
RA (Registration Authority)	Sertifikat so‘rovlarini tekshiradigan va CAga tasdiqlash uchun yuboradigan vosita.
Certificate (Sertifikat)	Foydalanuvchi yoki serverning jamoatchilik kaliti bilan birga identifikatsiyasini tasdiqlovchi raqamli hujjat.
Public Key	Asimmetrik shifrlashda ochiq kalit, ma’lumotni shifrlash yoki imzoni tekshirish uchun ishlatiladi.
Private Key	Maxfiy kalit, ma’lumotni shifrlashdan chiqarish yoki raqamli imzo qo‘yish uchun ishlatiladi.
CRL (Certificate Revocation List)	Bekor qilingan yoki amal qilish muddati tugagan sertifikatlar ro‘yxati.
OCSP (Online Certificate Status Protocol)	Sertifikat holatini real vaqt rejimida tekshirish protokoli.
🛠️ PKI jarayoni

Kalit juftligini yaratish
Foydalanuvchi yoki server private va public key juftligini yaratadi.

Sertifikat so‘rovini yuborish (CSR)
Foydalanuvchi CSR (Certificate Signing Request) yaratadi va RA/CAga yuboradi.

Identifikatsiyani tekshirish
RA foydalanuvchi identifikatsiyasini tekshiradi va CAga yuboradi.

Sertifikatni berish
CA foydalanuvchiga raqamli sertifikat beradi, unda jamoatchilik kaliti va identifikatsiya ma’lumotlari bo‘ladi.

Sertifikatni ishlatish
Sertifikat va kalitlar yordamida:

Ma’lumotlarni shifrlash va deshifrlash.

Raqamli imzo yaratish va tekshirish.

Foydalanuvchi yoki serverni autentifikatsiya qilish.

Sertifikat holatini tekshirish
Sertifikat amal qilish muddati tugagani yoki bekor qilinganini CRL yoki OCSP orqali tekshirish mumkin.

📌 Foydalanish sohalari

HTTPS va SSL/TLS xavfsizligi

Elektron pochta xavfsizligi (S/MIME)

VPN va korporativ tarmoqlar

Raqamli imzolar va hujjat autentifikatsiyasi

IoT qurilmalar xavfsizligi