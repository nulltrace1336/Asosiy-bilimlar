🛡️ Incident Response Jarayonlari

Incident Response (IR) — bu kiberxavfsizlik hodisasi (hujum, zaiflik ekspluatatsiyasi, ma’lumot oqishi va h.k.) sodir bo‘lganida tashkilotning tizimli javob berish jarayonidir. Maqsad: zararni kamaytirish, sababni aniqlash, tizimlarni tiklash va kelajakda shunday hodisalarni oldini olish.

1. Preparation (Tayyorlash)
Maqsad:

Hodisaga tayyor bo‘lish

Xodimlar va tizimlar uchun protseduralarni ishlab chiqish

Amalga oshiriladigan ishlar:

IR Plan yaratish

Hodisalarni aniqlash va xabar qilish tartibini belgilash

Zarur tools va platformalarni tayyorlash:

SIEM (Splunk, ELK)

Endpoint Detection & Response (Crowdstrike, SentinelOne)

Forensic tools (FTK, Autopsy)

Xodimlarni trening va drills bilan tayyorlash

2. Identification (Aniqlash)
Maqsad:

Hodisani tezda aniqlash

Hodisaning tabiati va ta’sirini baholash

Amalga oshiriladigan ishlar:

Log monitoring: firewall, IDS/IPS, server loglari

Anomal aktivlikni aniqlash:

Noma’lum login urinishlari

Ma’lumotlar oqimi o‘zgarishi

Malware yoki ransomwarening belgisi

Hodisa tasnifi:

Security Incident

Breach / Compromise

Policy Violation

3. Containment (Cheklash)
Maqsad:

Hodisaning tarqalishini oldini olish

Amalga oshiriladigan ishlar:

Short-term containment:

Zararlangan hostlarni tarmoqqa ulashni to‘xtatish

Zararlangan foydalanuvchi hisobini bloklash

Long-term containment:

Patchlarni qo‘llash

Zararlangan tizimlarni izolyatsiya qilish

Monitoringni kuchaytirish

4. Eradication (Yo‘q qilish)
Maqsad:

Hodisa sabablarini va zararli komponentlarni tizimdan olib tashlash

Amalga oshiriladigan ishlar:

Malware va zararli fayllarni o‘chirish

Vulnerabilitylarni patch qilish

Zararlangan foydalanuvchi hisoblarini tiklash

Qo‘shimcha tekshiruvlar (backdoor, persistence, rootkit)

5. Recovery (Tiklash)
Maqsad:

Tizimlarni normal ishga qaytarish

Yangi hodisalarni oldini olish

Amalga oshiriladigan ishlar:

Sistemalarni backupdan tiklash

Test va monitoring orqali tizim holatini tekshirish

Normal operatsiyalarga qaytarish

6. Lessons Learned (Sabak chiqarish)
Maqsad:

Hodisadan o‘rganish

Kelajakdagi xavflarni kamaytirish

Amalga oshiriladigan ishlar:

Hodisa hisobotini tayyorlash:

Hodisa tafsilotlari (qachon, qanday sodir bo‘ldi)

Javob choralari

Zararning miqdori

Security policy va IR planini yangilash

Xodimlar uchun treninglar o‘tkazish

🔹 Qo‘llanma tavsiyalari:

IR jarayoni doimiy takomillashtirilishi kerak

Hodisalarni SIEM bilan avtomatlashtirish foydali

Communication plan — hodisa vaqtida xodimlar va rahbariyat bilan tezkor aloqa uchun muhim

Documentation — har bir qadam yozib borilishi keyingi audit va sud ishlarida zarur