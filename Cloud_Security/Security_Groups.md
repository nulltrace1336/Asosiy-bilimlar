🔐 Security Groups nima?

Security Group (SG) — bu AWS’dagi virtual firewall bo‘lib, EC2 instansiyalari, RDS, Lambda va boshqa resurslar uchun kiruvchi (Inbound) va chiquvchi (Outbound) trafikni boshqaradi.

Security Groups stateful hisoblanadi.

Agar siz kiruvchi (inbound) trafikni ruxsat bersangiz, javobiy chiquvchi (outbound) trafik avtomatik ruxsat etiladi.

Har bir SG resursga bir yoki bir nechta bog‘lanishi mumkin.

⚙️ Security Groups xususiyatlari
Xususiyat	Tavsif
Stateful	Kiruvchi trafikga ruxsat berilsa, javob avtomatik ruxsat etiladi.
Default deny	Hech narsa ruxsat etilmagan bo‘lsa, trafik bloklanadi.
Inbound/Outbound qoidalari	Kiruvchi va chiquvchi trafikni boshqaradi.
IP yoki boshqa SG asosida ruxsat	Siz IP manzil, IP diapazon yoki boshqa SG’ni manba sifatida belgilashingiz mumkin.
Bir nechta SG bog‘lash	Bir instansiyaga bir nechta SG biriktirish mumkin.
📝 Security Group yaratish va ishlatish
1️⃣ Inbound qoida

Kiruvchi trafikni aniqlaydi.

Masalan:

HTTP: 80 port, manba 0.0.0.0/0

SSH: 22 port, manba 203.0.113.5/32

2️⃣ Outbound qoida

Chiquvchi trafikni aniqlaydi.

Default holatda, barcha chiqishlar ruxsat etilgan (0.0.0.0/0).

💡 Maslahatlar

Minimal ruxsat printsipi — faqat zarur portlarni oching.

IP bo‘yicha cheklash — imkon qadar manbalarni aniq IP bilan cheklang.

SG’larni nomlash — maqsad va instansiya bilan bog‘liq aniq nom berish.

Audit qilish — vaqti-vaqti bilan qoidalarni tekshirib boring.