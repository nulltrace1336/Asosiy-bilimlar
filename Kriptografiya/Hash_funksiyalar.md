# Hash Funksiyalari (MD5, SHA256)

## 📌 Hash Funksiyasi nima?
Hash funksiyasi — bu **istalgan uzunlikdagi ma’lumotni (matn, fayl, parol va boshqalar)** oladigan va uni **aniq o‘lchamdagi hash qiymatiga** (digest) aylantiradigan matematik funksiya. Hash funksiyalari asosan quyidagi maqsadlarda ishlatiladi:

- Ma’lumotlarni **bir xillik tekshirish** (integrity check)
- Parollarni **saqlash** va tekshirish
- Raqamli imzolar va kriptografiyada
- Fayl identifikatori (checksums)

Hash funksiyalari quyidagi xususiyatlarga ega bo‘lishi kerak:

1. **Deterministik**: bir xil kirish ma’lumotidan har doim bir xil hash hosil bo‘ladi.
2. **Tez hisoblanadigan**: hisoblash tez amalga oshadi.
3. **Pre-image resistance**: hash qiymatdan asl ma’lumotni topish qiyin bo‘lishi kerak.
4. **Collision resistance**: ikki turli kirish ma’lumotlari bir xil hash qiymatga ega bo‘lmasligi kerak.
5. **Avalanche effect**: kirishdagi kichik o‘zgarish hash qiymatni sezilarli darajada o‘zgartiradi.

---

## 🔹 Mashhur Hash Algoritmlari

### 1. MD5 (Message Digest 5)
- **Hash uzunligi:** 128-bit (16 bayt)
- **Ishlash tezligi:** Juda tez
- **Afzalliklari:** Tez, oddiy implementatsiya, fayl tekshirish uchun ishlatiladi.
- **Kamchiliklari:** Xavfsiz emas, collision (to‘qnashuv) topish mumkin.
- **Qo‘llanishi:** Fayl integritetini tekshirish, eski tizimlar.

**Misol:**
Input: "hello"
MD5 hash: 5d41402abc4b2a76b9719d911017c592

markdown
Copy code

---

### 2. SHA-256 (Secure Hash Algorithm 256-bit)
- **Hash uzunligi:** 256-bit (32 bayt)
- **Afzalliklari:** Xavfsiz, collision topish juda qiyin
- **Kamchiliklari:** MD5 ga qaraganda sekinroq
- **Qo‘llanishi:** Kriptografik tizimlar, blockchain, parol saqlash

**Misol:**
Input: "hello"
SHA256 hash: 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

yaml
Copy code

---

## ⚡ Hash Funksiyalari Farqi (MD5 vs SHA256)

| Xususiyat          | MD5                | SHA256             |
|-------------------|------------------|------------------|
| Hash uzunligi      | 128-bit           | 256-bit           |
| Xavfsizlik         | Kam, collision mavjud | Yuqori, collision qiyin |
| Tezlik             | Juda tez          | Nisbatan sekin    |
| Qo‘llanish         | Fayl tekshirish, eski tizim | Kripto, blockchain, xavfsiz parol saqlash |