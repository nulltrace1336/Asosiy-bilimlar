# Broken Access Control

**Broken Access Control** – bu veb-ilovalarda foydalanuvchi ruxsatlarini noto‘g‘ri boshqarish natijasida yuzaga keladigan xavfsizlik muammosi. Bu xatolik foydalanuvchiga o‘ziga ruxsat berilmagan resurslarga kirish imkonini beradi, masalan, boshqa foydalanuvchining ma’lumotlarini ko‘rish, o‘zgartirish yoki o‘chirish.

OWASP Top 10 2021 ro‘yxatida bu **A01:2021 – Broken Access Control** sifatida ajratilgan.

---

## 1. Broken Access Control turlari

| Tur | Tavsifi | Misol |
| --- | ------- | ----- |
| **Vertical Privilege Escalation** | Foydalanuvchi yuqori darajadagi foydalanuvchi ruxsatlariga ega bo‘lishga urinadi | Oddiy foydalanuvchi admin panelga kiradi |
| **Horizontal Privilege Escalation** | Foydalanuvchi o‘ziga teng bo‘lgan boshqa foydalanuvchi ma’lumotlariga kiradi | Foydalanuvchi boshqa foydalanuvchining profilini o‘zgartiradi |
| **Unrestricted Access** | Hech qanday tekshiruvsiz resursga kirish mumkin | URL orqali boshqa foydalanuvchi faylini ko‘rish |
| **Insecure Direct Object References (IDOR)** | Foydalanuvchi ob’ekt identifikatorlarini o‘zgartirib resursga kiradi | `/invoice/123` → `/invoice/124` |

---

## 2. Broken Access Control sabablar

- Ruxsatlarni server tomonida tekshirmaslik (faqat front-endda tekshirish)
- Noaniq yoki noto‘g‘ri rol siyosati
- Default konfiguratsiyalarda barcha foydalanuvchilarga ochiq resurslar
- API-larda autentifikatsiya va avtorizatsiya tekshiruvlarining yetishmasligi
- URL yoki parametrlarni foydalanuvchi tomonidan boshqariladigan tarzda ishlatish

---

## 3. Aniqlash usullari

1. **Manual Testing**
   - URL-larni o‘zgartirib kirishni sinash
   - Boshqa foydalanuvchi ID-larini ishlatib kirish
   - Rol o‘zgartirish (user → admin) imkoniyatlarini tekshirish

2. **Automated Tools**
   - Burp Suite – **Scanner & Intruder**
   - OWASP ZAP – Active Scan
   - Postman / API testing bilan ruxsatlarni tekshirish

3. **Penetration Testing Methodologies**
   - Horizontal va vertical privilege escalation sinovlari
   - IDOR va unrestricted file access sinovlari
   - API endpointlarni rol va tokenlar bilan tekshirish

---

## 4. Oldini olish va himoya qilish

1. **Server-side enforce access control**
   - Har bir resurs va endpoint uchun ruxsatlarni serverda tekshirish
2. **Least Privilege Principle**
   - Foydalanuvchilarga minimal zarur ruxsat berish
3. **Dasturiy xavfsizlik qoidalari**
   - Role-based access control (RBAC)
   - Attribute-based access control (ABAC)
4. **Doimiy tekshiruv va monitoring**
   - Audit loglar va alert tizimlari
5. **IDOR va parametrlarni xavfsiz ishlatish**
   - Foydalanuvchi o‘zgartira olmaydigan token yoki UUID ishlatish
6. **Qo‘shimcha xavfsizlik**
   - Multi-factor authentication (MFA) bilan yuqori darajali ruxsatlar
   - Rate limiting va session management

---

## 5. Misollar

### 5.1 IDOR misoli
URL:  
https://example.com/user/profile?id=123

yaml
Copy code
Foydalanuvchi `id=124` ga o‘zgartirsa, boshqa foydalanuvchi profilini ko‘rishi mumkin.

### 5.2 Vertical Privilege Escalation misoli
- Oddiy foydalanuvchi admin panelga `/admin` URL orqali kira oladi, chunki server rol tekshiruvini bajarmaydi.

---

## 6. Resurslar
- [OWASP Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)