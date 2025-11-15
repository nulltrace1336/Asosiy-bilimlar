# Cryptographic Failures (OWASP Top 10)

Cryptographic Failures — bu xavfsizlik muammolari bo‘lib, ular ma’lumotlarni noto‘g‘ri yoki zaif shifrlash orqali himoya qilinmaganida yuzaga keladi. Ushbu xatoliklar foydalanuvchi ma’lumotlarini, parollarni, tokenlarni, shaxsiy ma’lumotlarni va boshqa sezgir ma’lumotlarni osonlik bilan o‘g‘irlashga imkon beradi.

---

## 1. Xatolik sabablari

- **Zaif yoki eskirgan algoritmlar** ishlatish (MD5, SHA1, DES, RC4)  
- **Ma’lumotlarni shifrlamaslik** (sensitive data plain text saqlash)  
- **Shifrlash kalitlarini noto‘g‘ri boshqarish**  
- **Transport qatlamida himoyasizlik** (HTTP o‘rniga HTTPS ishlatmaslik)  
- **Parollarni xotirada yoki fayllarda plain text saqlash**  
- **Kriptografik protokollarni noto‘g‘ri konfiguratsiya qilish**  

---

## 2. Xavf turlari

| Xavf turi | Tavsif |
|-----------|--------|
| Ma’lumotni o‘g‘irlash | Zaif shifrlash yoki shifrlamaslik tufayli ma’lumotlar oson o‘g‘irlanadi |
| Foydalanuvchi parollarini buzish | Zaif hashing algoritmlari tufayli parollarni tezda topish mumkin |
| Sessiya yoki tokenlarni o‘g‘irlash | HTTPS ishlatilmagan yoki token shifrlanmagan bo‘lsa, hujumchi ularni oson o‘g‘irlashi mumkin |
| Kripto kalitlarini yo‘qotish | Noto‘g‘ri saqlash yoki almashish tufayli kalitlar buziladi |

---

## 3. Aniqlash usullari

1. **Ma’lumotlar bazasi tahlili**
   - Parollar, tokenlar va boshqa sensitive data plain textda saqlanayotganini tekshirish
2. **Shifrlash algoritmlari audit**
   - MD5, SHA1, DES, RC4 kabi eskirgan algoritmlarni aniqlash
3. **HTTPS tekshiruvi**
   - Transport qatlamida TLS ishlatilayotganini tekshirish
4. **Kripto kalitlar audit**
   - Kalitlar noto‘g‘ri joyda saqlanmaganligini tekshirish
5. **Dynamic Analysis**
   - Pentest vositalari orqali ma’lumotlarni osonlik bilan o‘g‘irlash mumkinligini aniqlash

---

## 4. Chora-tadbirlar

- **Zaif algoritmlardan voz kechish**
  - SHA256, SHA3, AES-256, RSA 2048+ kabi zamonaviy va ishonchli algoritmlardan foydalanish
- **Ma’lumotlarni shifrlash**
  - Sensitive data (parol, kredit karta, SSN, token) shifrlangan holda saqlanishi kerak
- **Parollarni xavfsiz saqlash**
  - `bcrypt`, `scrypt`, yoki `Argon2` kabi adaptive hashing algoritmlarini ishlatish
- **Transport qatlamini himoya qilish**
  - HTTPS/TLS orqali barcha ma’lumotlar uzatilishini majburiy qilish
- **Kalitlarni boshqarish**
  - Kalitlarni xavfsiz joyda saqlash (HSM, KMS), kod ichida saqlamaslik
- **Regulyar audit va test**
  - Kriptografik amaliyotlarni muntazam audit qilish va penetration test o‘tkazish
- **Shifrlash protokollarini to‘g‘ri sozlash**
  - TLS 1.2/1.3, Perfect Forward Secrecy, va sertifikatlarni tekshirish

---

## 5. Misol

**Noto‘g‘ri amaliyot:**

```python
# Noto‘g‘ri: MD5 ishlatilgan
import hashlib
password = "mypassword"
hash = hashlib.md5(password.encode()).hexdigest()
To‘g‘ri amaliyot:

python
Copy code
# To‘g‘ri: bcrypt ishlatilgan
import bcrypt

password = b"mypassword"
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password, salt)
6. Qo‘shimcha manbalar
OWASP Cryptographic Failures

NIST Recommendations on Hashing and Encryption

markdown
Copy code
