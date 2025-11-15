🖥️ Digital Forensics: Disk va Memory Analysis
📌 Kirish

Digital Forensics — bu raqamli qurilmalardan dalillarni yig‘ish, saqlash, tahlil qilish va huquqiy jihatdan tasdiqlash jarayoni.
Disk va memory tahlili kiberxavfsizlik hodisalarini aniqlash va tekshirishda muhim ahamiyatga ega.

1️⃣ Disk Analysis (Disk Forensics)
Maqsad

Foydalanuvchi faoliyati va tizimdagi hodisalarni aniqlash

O‘chirilgan fayllarni tiklash

Zararli dastur va logslarni tahlil qilish

Asboblar
Tur	Asboblar/Usullar
Imaging	dd, FTK Imager, Guymager
File System Analysis	Autopsy, Sleuth Kit, X-Ways Forensics
Recovery & Carving	PhotoRec, Foremost, Scalpel
Timeline Analysis	log2timeline, Plaso, Timesketch
Jarayon

Diskni tasvirlash (Imaging)

Original diskni o‘zgartirmasdan nusxasini olish (dd, FTK Imager)

File system tahlili

NTFS, FAT, EXT4 fayl tizimlarini tahlil qilish

O‘chirilgan fayllarni qidirish va tiklash

Fayl va loglarni tekshirish

Windows Event Logs, syslog, brauzer tarixlari

Timeline yaratish

Hodisalarni vaqt ketma-ketligi bilan ko‘rsatish

2️⃣ Memory Analysis (RAM Forensics)
Maqsad

Ishlayotgan jarayonlarni aniqlash

Malware yoki rootkitlarni topish

Tarmoq sessiyalarini va credentiallarni olish

Asboblar
Tur	Asboblar/Usullar
Acquisition	DumpIt, FTK Imager, LiME (Linux)
Analysis	Volatility, Rekall, Redline
Process & Network Analysis	Volatility plugins, netscan, pslist
Jarayon

Memory tasvirini olish (Acquisition)

RAMni to‘liq nusxalash (DumpIt, LiME)

Jarayonlar va servislarni tekshirish

Ishlayotgan protsesslar, DLL-lar va servislar

Volatility: pslist, pstree

Tarmoq sessiyalari va ochiq portlar

Volatility: netscan, connscan

Credential va sensitive ma’lumotlarni qidirish

Browser passwords, Windows credentials (hashdump, lsadump)

Malware va rootkit aniqlash

Process injection, hidden processes, suspicious modules

3️⃣ Best Practices

Disk va memory nusxasini olishda write-blocker yoki read-only vositalardan foydalanish

Dalillarni hash bilan tekshirish (MD5, SHA256)

Analiz jarayonida original ma’lumotni o‘zgartirmaslik

Hujjatlashtirish: har bir qadamni yozib borish

4️⃣ Foydali Resurslar

SANS Digital Forensics Resources

Volatility Framework Documentation

Autopsy User Guide