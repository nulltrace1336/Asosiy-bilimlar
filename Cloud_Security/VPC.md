VPC nima?

VPC — bu bulut provayderida (AWS, Azure, GCP) foydalanuvchi tomonidan ajratilgan virtual izolyatsiyalangan tarmoq. U orqali siz o‘z bulut resurslaringiz (EC2, RDS, Lambda va boshqalar) uchun xususiy IP-manzillar, subnetlar, routing va xavfsizlik siyosatlarini belgilashingiz mumkin.

VPC sizga an’anaviy on-premises tarmoqlar kabi boshqaruv va xavfsizlikni beradi, lekin bulut infratuzilmasida.

VPCning asosiy komponentlari
Komponent	Tavsif
Subnet	VPC ichidagi kichik tarmoq bo‘lagi (Public/Private).
Route Table	Trafik qayerga yo‘naltirilishini belgilaydi.
Internet Gateway (IGW)	VPCni internetga ulash imkonini beradi.
NAT Gateway / NAT Instance	Private subnetdagi resurslarga internetga chiqish imkonini beradi, lekin ularga internetdan kirish yo‘q.
Security Group	Resurs darajasidagi virtual firewall, kirish/chiqish qoidalari bilan.
Network ACL (NACL)	Subnet darajasidagi firewall, kirish/chiqish qoidalari bilan.
Elastic IP	Statik internet IP-manzil, resursga biriktiriladi.
VPC Peering / VPN / Direct Connect	Turli VPClarni yoki on-premises tarmoqlarni birlashtirish usullari.
VPCning turlari

Public VPC / Public Subnet

Resurslar internetga kirishi mumkin (EC2, Load Balancer).

Private VPC / Private Subnet

Internetdan to‘g‘ridan-to‘g‘ri kirish yo‘q, faqat NAT orqali chiqishi mumkin.

Hybrid VPC

On-premises tarmoq bilan bog‘langan aralash konfiguratsiya.

VPC afzalliklari

Resurslarni izolyatsiya qilish va xavfsizlikni oshirish.

Tarmoq konfiguratsiyasini moslashuvchan boshqarish (IP manzillar, subnetlar).

Internet yoki boshqa VPClar bilan xavfsiz bog‘lanish imkoniyati.

Bulutda korporativ tarmoqni simulyatsiya qilish.