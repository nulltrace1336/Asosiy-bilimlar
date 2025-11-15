AWS IAM nima?

AWS IAM — bu Amazon Web Services (AWS) ichida resurslarga kim va qanday kirish huquqiga ega ekanligini boshqarish xizmati.
U orqali siz foydalanuvchilar, guruhlar, rollar va siyosatlar orqali xavfsiz va moslashtirilgan kirish nazoratini amalga oshirishingiz mumkin.

Asosiy maqsadlari:

Foydalanuvchilar va xizmatlar uchun xavfsiz kirishni ta’minlash.

“Minimum privilege” printsipini qo‘llash (faqat kerakli ruxsatlarni berish).

AWS resurslariga kirishni markazlashtirilgan tarzda boshqarish.

Asosiy komponentlar
Komponent	Tavsif
User (Foydalanuvchi)	IAM foydalanuvchisi AWS resurslariga kirish huquqiga ega shaxs yoki xizmat hisobidir.
Group (Guruh)	Foydalanuvchilarni guruhlash orqali ruxsatlarni bir martada boshqarish imkonini beradi.
Role (Roli)	Muayyan ruxsatlar bilan vaqtincha ishlatiladigan hisob. Masalan, EC2 instansiyasi S3 ga kirishi kerak bo‘lsa, role ishlatiladi.
Policy (Siyosat)	JSON formatida yozilgan ruxsatlar to‘plami. Foydalanuvchi, guruh yoki roliga biriktiriladi.
Permission (Ruxsat)	Har bir siyosat orqali belgilangan aniq huquqlar (read, write, delete, list va h.k.).
MFA (Multi-Factor Authentication)	Qo‘shimcha xavfsizlik qatlamini qo‘shish uchun ishlatiladi.
IAM turlari

IAM User – Shaxsiy AWS hisoblar uchun.

IAM Group – Ko‘plab foydalanuvchilar uchun ruxsatlarni boshqarish.

IAM Role – AWS xizmatlari yoki tashqi akkauntlarga vaqtinchalik ruxsat berish.

IAM Policy – JSON fayl orqali ruxsatlarni aniqlash.

IAM Identity Federation – Tashqi identitet (AD, Google Workspace, SAML) orqali AWS ga kirishni ta’minlash.

IAM siyosat turlari
Tur	Tavsif
Managed Policies	AWS tomonidan tayyorlangan siyosatlar yoki foydalanuvchi yaratgan boshqariladigan siyosatlar.
Inline Policies	Foydalanuvchi, guruh yoki rolga maxsus biriktirilgan siyosat.
IAM xavfsizlik tavsiyalari

Root accountni minimal ishlatish – Asosiy hisobdan faqat zarur hollarda foydalaning.

MFA o‘rnatish – Root va muhim foydalanuvchilar uchun.

Minimal ruxsatlar printsipi – Foydalanuvchiga faqat kerakli ruxsatlarni bering.

Role va policy qayta ishlatish – Inline policies o‘rniga managed policies ishlating.

Audit qilish – AWS CloudTrail orqali IAM faoliyatini kuzatib boring.