# Security Misconfiguration

**Security Misconfiguration** — bu veb-ilovalar, serverlar, API yoki boshqa tizimlarda xavfsizlik sozlamalari noto‘g‘ri yoki yetarli darajada amalga oshirilmagan holatlarni anglatadi. Bu zaiflik hujumchilarga tizimga ruxsatsiz kirish, ma’lumotlarni o‘g‘irlash yoki xizmatni to‘xtatib qo‘yish imkonini beradi.

---

## Sabablari

1. **Default konfiguratsiyalar ishlatilishi**  
   - Standart parollar va foydalanuvchi nomlari o‘zgartirilmagan bo‘lishi.  
   - Tizim yoki serverlarni o‘rnatishda default sozlamalar ishlatiladi.

2. **Ortiqcha funksiyalar va xizmatlar**  
   - Keraksiz portlar ochiq qolishi.  
   - Keraksiz modullar yoki paketlar o‘rnatilgan bo‘lishi.

3. **Xato konfiguratsiya fayllari**  
   - Konfiguratsiya fayllari Internetga ochiq bo‘lishi.  
   - Fayllarda sezgir ma’lumotlar (API kalitlari, parollar) saqlangan bo‘lishi.

4. **Tizim yangilanishlarini qilmaslik**  
   - Operatsion tizim va kutubxonalar eskirgan va patch qilinmagan bo‘lishi.

5. **Xato ruxsatlar va ACL**  
   - Foydalanuvchi va fayl ruxsatlari noto‘g‘ri berilgan bo‘lishi.

---

## Namunalari

- Administrator panelining default URL yoki login ma’lumotlari o‘zgartirilmagan.  
- Apache, Nginx, Tomcat kabi serverlarda kerakmas modul yoki directory listing yoqilgan.  
- Cloud xizmatlarda (AWS S3, Azure Blob) public ruxsatlar noto‘g‘ri berilgan.  
- Xatolik sahifalarida ichki tizim haqidagi ma’lumotlar (stack trace) ko‘rsatiladi.

---

## Xavf va ta’sirlari

- **Ma’lumotlarni o‘g‘irlash**: foydalanuvchi ma’lumotlari yoki API kalitlari.  
- **Hisoblar va sessiyalarga ruxsatsiz kirish**.  
- **Dastur yoki serverni boshqarish huquqini yo‘qotish**.  
- **Xizmatni to‘xtatish (DoS/DDoS)**.  
- **Keng miqyosli zaifliklar**: boshqa zaifliklar bilan birga ishlatilganda katta xavf tug‘diradi.

---

## Aniqlash usullari

1. **Automatlashtirilgan skanerlar**  
   - OWASP ZAP, Nessus, Nikto.  

2. **Qo‘l bilan testlash**  
   - Konfiguratsiya fayllari va URL’larni tekshirish.  
   - Server headerlari va xatolik sahifalarini tahlil qilish.  

3. **Cloud konfiguratsiya auditlari**  
   - AWS Config, Azure Security Center.  

---

## Oldini olish va chora-tadbirlar

1. **Default sozlamalarni o‘zgartirish**  
   - Parollar, admin nomlari va portlarni o‘zgartirish.  

2. **Keraksiz xizmat va portlarni o‘chirish**  
   - Minimal xizmatlar bilan ishlash.  

3. **Konfiguratsiya fayllarini himoyalash**  
   - Fayllarga faqat kerakli ruxsatlarni berish.  
   - Maxfiy ma’lumotlarni saqlamaslik.  

4. **Tizim va dasturlarni doimiy yangilash**  
   - Patch va security update’larni vaqtida qo‘llash.  

5. **Xatolik va loglarni to‘g‘ri boshqarish**  
   - Ichki tizim ma’lumotlarini xatolik sahifalarida ko‘rsatmaslik.  

6. **Security misconfiguration testing**  
   - Regular audit va penetration testing.  

---

## Foydali resurslar

- [OWASP Security Misconfiguration](https://owasp.org/Top10/A06_2021-Security_Misconfiguration/)  
- [OWASP Cheat Sheet – Security Misconfiguration](https://cheatsheetseries.owasp.org/cheatsheets/Security_Misconfiguration_Cheat_Sheet.html)  

