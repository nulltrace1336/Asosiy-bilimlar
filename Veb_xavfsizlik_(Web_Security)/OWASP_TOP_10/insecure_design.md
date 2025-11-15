# OWASP Top 10 2021 – Insecure Design

## Tavsifi
**Insecure Design** – bu dasturiy ta’minotning xavfsizligini oldindan hisobga olmasdan yoki yetarlicha himoya mexanizmlarsiz ishlab chiqilishi natijasida yuzaga keladigan xavflar majmuasidir. Bu xato dastur arxitekturasi yoki dizayn bosqichida paydo bo‘ladi va kod yozilganidan keyin tuzatish qiyin bo‘lishi mumkin.

Boshqacha aytganda, Insecure Design – bu "xavfsizlikni hisobga olmaslik"dan kelib chiqqan zaiflik bo‘lib, ko‘pincha quyidagi omillar bilan bog‘liq:

- Noaniq xavfsizlik talablarini ishlab chiqishda e’tiborsiz qoldirish
- Autentifikatsiya va avtorizatsiya mexanizmlarini noto‘g‘ri loyihalash
- Ma’lumotlarni shifrlash va xavfsiz saqlashni inobatga olmaslik
- Ishonchsiz komponentlar yoki kutubxonalarni ishlatish

---

## Misollar
1. **Autentifikatsiya va avtorizatsiyada zaif dizayn**  
   - Parol siyosati mavjud emas yoki juda zaif  
   - Multi-factor autentifikatsiya (MFA) qo‘llanilmagan

2. **Ma’lumotlarni shifrlash bilan bog‘liq xatolar**  
   - Xususiy ma’lumotlarni shifrlamasdan saqlash  
   - Shifrlash algoritmlari eskirgan yoki zaif

3. **Noaniq xavfsizlik talablarining dastur dizaynida aks etmasligi**  
   - Ruxsatlar va cheklovlar noto‘g‘ri taqsimlangan  
   - API endpointlarining xavfsizligi hisobga olinmagan

4. **Xavfsiz arxitektura prinsiplariga rioya qilmaslik**  
   - Least Privilege (eng kam ruxsat) tamoyili buzilgan  
   - Input validation (kirish ma’lumotlarini tekshirish) dizaynda ko‘zda tutilmagan

---

## Xavf-xatarlar
- Ma’lumotlar o‘g‘irlanishi yoki buzilishi  
- Foydalanuvchi akkauntlarining noqonuniy foydalanilishi  
- Ilovaning butunligi va ishlashiga xavf  
- Ruxsatsiz ma’lumot oqimi yoki eskalatsiya  

---

## Aniqlash usullari
- **Threat Modeling** – xavf tahlili orqali dizayn bosqichida zaifliklarni aniqlash  
- **Security Reviews** – kod va arxitektura sharhlari  
- **Penetration Testing** – tizimni ekspluatatsiya qilishga urinishlar orqali zaifliklarni aniqlash  

---

## Chora-tadbirlar
1. **Xavfsizlikni dizayn bosqichida hisobga olish**  
   - Secure by Design printsipi  
   - Risklarni baholash va threat modeling

2. **Autentifikatsiya va avtorizatsiya mexanizmlarini kuchaytirish**  
   - MFA qo‘llash  
   - Role-based Access Control (RBAC) tizimini joriy etish

3. **Ma’lumotlarni himoya qilish**  
   - Transport va storage uchun shifrlash  
   - Sensitive data masking va tokenization

4. **Xavfsiz arxitektura tamoyillariga rioya qilish**  
   - Least Privilege printsipi  
   - Input validation va output encoding  
   - Komponentlar va kutubxonalarni muntazam yangilash

5. **Doimiy xavfsizlik tekshiruvlari**  
   - Kod auditlari  
   - Security testing va vulnerability scanning  

---

## Xulosa
Insecure Design – dasturiy ta’minot xavfsizligida eng muhim va oldini olish qiyin bo‘lgan zaifliklardan biri. Uni aniqlash va bartaraf etish dastur ishlab chiqishning dastlabki bosqichlarida amalga oshirilishi lozim. Xavfsizlikni dizayn bosqichida inobatga olish orqali katta moliyaviy va obro‘ zararidan saqlanish mumkin.
