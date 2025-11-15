Azure AD nima?

Azure Active Directory (Azure AD) — bu Microsoft tomonidan taqdim etilgan bulutga asoslangan identifikatsiya va kirish boshqaruv xizmati. U korxonalarga foydalanuvchilar, guruhlar va ilovalarga kirishni markazlashtirilgan tarzda boshqarish imkonini beradi.

Azure AD klassik Windows Active Directory (on-premises AD) bilan arxitekturasi jihatidan farq qiladi, chunki u to‘liq bulutga asoslangan va internet orqali ishlaydi.

Asosiy funksiyalari
Funksiya	Tavsif
Identifikatsiya boshqaruvi	Foydalanuvchilar va guruhlar yaratish, autentifikatsiya va avtorizatsiya qilish.
SSO (Single Sign-On)	Foydalanuvchilar bitta login orqali ko‘plab ilovalarga kirishi mumkin.
Multi-Factor Authentication (MFA)	Xavfsizlikni oshirish uchun qo‘shimcha autentifikatsiya (sms, app, token).
Conditional Access	Kirish siyosatlarini shartlarga qarab belgilash (IP manzili, qurilma, joylashuv).
B2B Collaboration	Tashqi hamkorlar va sheriklar bilan xavfsiz ishlash.
B2C Identity Management	Mijozlarga (consumer) autentifikatsiya va ro‘yxatdan o‘tish xizmatlari.
Device Management	Qurilmalarni ro‘yxatdan o‘tkazish va ularni boshqarish.
Monitoring va Reporting	Kirishlar, xavfsizlik hodisalari va auditlar bo‘yicha hisobotlar.
Azure AD va klassik AD farqi
Xususiyat	Klassik AD	Azure AD
Joylashuv	On-premises (mahalliy serverlar)	Bulut (Microsoft Azure)
Protokollar	LDAP, Kerberos	OAuth 2.0, SAML, OpenID Connect
Foydalanuvchi kirishi	Lokal domain	Internet orqali (SSO)
Qurilmalar bilan ishlash	Domain join qilinadi	Intune orqali device management yoki hybrid join
Azure AD ni ishlatish holatlari

Korxona foydalanuvchilarini bulut ilovalarga (Office 365, Teams, Salesforce) kirish uchun boshqarish.

Tashqi hamkorlar bilan xavfsiz B2B hamkorlik qilish.

Mobil va remote ishchilar uchun shartli kirish siyosatlarini qo‘llash.

Xavfsizlikni oshirish (MFA, Conditional Access).