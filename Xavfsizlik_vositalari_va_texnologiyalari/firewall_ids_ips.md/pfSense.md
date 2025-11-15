1) pfSense nima va qachon ishlatish kerak

pfSense — ochiq manbali, FreeBSD asosida ishlaydigan tarmoq firewall va router yechimi. U korxona va home-lab darajasidagi funktsiyalarni taklif qiladi: stateful firewall, NAT, VLAN, multi-WAN, load balancing, VPN (OpenVPN, IPsec, WireGuard), paketlar orqali IDS/IPS/qo‘shimcha funktsiyalar. Rasmiy hujjatlar va o‘rnatish ko‘rsatmasi netgate/pfSense saytida bor. 
pfsense.org
+1

2) Qaysi pfSense variantlari bor

pfSense Community Edition (CE) — bepul, keng foydalaniladigan versiya. 
pfsense.org

pfSense Plus / Netgate appliances — Netgate tomonidan tarqatiladigan qo‘llab-quvvatlangan versiyalar va tayyor apparat qurilmalar.

3) Apparatura va virtualizatsiya: nima tanlash kerak

Home lab / kichik ofis: 2-4 CPU yadrosi, 4–8 GB RAM, SSD (OS uchun), kamida 2 NIC (WAN + LAN).

Katta ofis / 1 Gbit+ trafik: ko‘proq CPU ko‘prosesori, 16GB+ RAM, 10GbE NIC (Intel/X710 yoki Netgate tavsiyalari), va hardware offload haqida o‘ylang.

Virtual mashina: Proxmox, ESXi, yoki Hyper-V ustida VM sifatida yaxshi ishlaydi (lekin NIC pass-through zudlik bilan tavsiya qilinadi). Rasmiy o‘rnatish qo‘llanmasi o‘qilishi lozim. 
docs.netgate.com

4) O‘rnatish — bosqichma-bosqich (tezkor)

Media tayyorlash: pfSense rasmiy saytidan ISO/USB image yuklab oling. 
pfsense.org

Boot va o‘rnatish: install wizard-ga rioya qilib diskga o‘rnating (USB yoki SSD). Installer o‘rnatish/tuzatish holatlarini qayta tiklash imkoniyatlarini ham taklif qiladi. 
docs.netgate.com

Dastlabki tarmoq interfeyslari: tizimni birinchi marta ishga tushirganda WAN va LAN interfeyslarini belgilang.

Web GUI-ga kirish: LAN orqali brauzerda https://<LAN_IP>/ manziliga kirib Admin hisob bilan konfiguratsiya qilinadi (default login o‘rnatish mexanizmi o‘rnatish vaqtida ko‘rsatiladi).

Initial Setup Wizard: IP konfiguratsiya, DNS, gateway va vaqt zonasi — wizard orqali tez sozlanadi. 
docs.netgate.com

5) Dastlabki konfiguratsiya (must do)

Admin parolni almashtiring va management GUI-ni faqat LAN ichidan yoki management VLAN orqali ruxsat eting.

Zaxira/rollback konfiguratsiyalarni yoqing va konfiguratsiyani yuklab oling.

Bog‘lanishlarni tekshirish: WAN gateway, DNS va Internetga chiqishni sinab ko‘ring.

Update tekshiruvi: yangi versiyalar va patchlarni tekshiring (rivojlanayotgan CE va Plus relizlariga diqqat). 
docs.netgate.com
+1

6) Asosiy tarmoq elementlari va amaliy misollar
a) Firewall qoidalari (stateful)

PfSense-da qoidalar “interface”ga bog‘langan: LAN qoidalari LAN interfeysida, WAN qoidalari WAN interfeysida ko‘riladi.

Qoidalarni yuqoridan pastga tartib bilan ishlaydi — birinchi mos kelgan qoida amal qiladi.

Oddiy misol — LAN dan Internetga ruxsat:

Interface: LAN

Action: Pass

Protocol: any

Source: LAN net

Destination: any

b) NAT / Port Forwarding

Static NAT (1:1) va Port Forward (masalan, HTTP port 80 yoki 443) interfeyslar orqali sozlanadi.

Qoida yaratgandan so‘ng firewall qoidasi avtomatik qo‘shilishi mumkin (option mavjud).

c) DHCP va DNS

DHCP server har bir interface uchun yoqilishi mumkin (range, static mappings).

DNS Resolver/Forwarder: pfSense unbound (resolver) yoki dnsmasq (forwarder) orqali xizmat qiladi. Lokal host nomlarini rezolyutsiya qilish uchun host overrides ishlatiladi.

d) VLANlar (802.1Q)

Switch qo‘llab-quvvatlasa, pfSense-da VLAN interfeyslarini yaratib, har bir VLAN uchun alohida interface, DHCP va firewall qoidalarini belgilash mumkin.

e) Multi-WAN va Load Balancing

Bir nechta Internet ulanishi bo‘lsa, gateway groups yaratib, failover yoki load balancing konfiguratsiya qilish mumkin.

(UX: firewall qoidalari, NAT va DHCP bo‘yicha rasmiy qo‘llanma va misollar uchun docs o‘qishni tavsiya qilaman). 
docs.netgate.com

7) VPN: OpenVPN, IPsec, WireGuard

OpenVPN: GUI orqali easy-RSA bilan server yoki client konfiguratsiyasi. Ko‘pincha site-to-site va remote-access uchun ishlatiladi.

IPsec: ko‘proq korporativ S2S tunellar uchun; tez-tez gateway/phase1/phase2 parametrlarini to‘g‘ri sozlash talab etiladi.

WireGuard: oddiy va yuqori tezlikdagi opsiya — pfSense-ga paket orqali o‘rnatiladi, ammo HA/CARP bilan integratsiyasi va state sync haqida e’tibor talab etadi (ba’zi murakkabliklar bor). 
pfsense.org
+1

8) Muhim paketlar (packages) — nima va nima uchun

pfBlockerNG — IP/Geo bloklash, DNSBL orqali reklam va tracking bloklash; home/office filtrlash uchun juda foydali.

Suricata yoki Snort — tarmoq IDS/IPS (Suricata ko‘p yadrodan foydalanadi). Inline (IPS) yoki monitoring rejimi bilan ishlatish mumkin.

Zenarmor / Sensei — ilova darajasidagi filtr, web-filter va tahlil.

HAProxy — reverse proxy va load balancer.

OpenVPN Client Export — OpenVPN konfiguratsiyasini export qilishni osonlashtiradi.
Paketlar repository yoki GUI => System => Package Manager orqali o‘rnatiladi. 
LinuxBlog.io

9) High Availability (HA) — CARP, pfsync va konfiguratsiya sinxronizatsiyasi

CARP (Common Address Redundancy Protocol) yordamida ikki pfSense instansiyasini Active/Passive cluster’ga sozlash mumkin (VIP — virtual IP manzil ishlaydi).

pfsync — stateful tarmoqlarni sinxronlashtirish (session/state replication) uchun.

konfiguratsiya sync — user, firewall rule, va paket konfiguratsiyalarini sinxronlashtirish mumkin. HA ni joriy etish — muhim va sinov talab qiladi (VPN va ba’zi paketlar bilan moslikdan avval tekshirish zarur). 
docs.netgate.com
+1

10) Zaxira, yangilash va monitoring

Zaxira (backup): System → Backup/Restore orqali muntazam eksport qiling. Avtomatlashtirish uchun cron + scp/rsync ham qo‘shish mumkin.

Yangilash: Releases va upgrade qo‘llanmalarini o‘qib yangilang — CE va Plus o‘rtasidagi migratsiya bo‘yicha hujjatlar mavjud. Yangilashdan oldin konfiguratsiya zaxirasini saqlang. 
docs.netgate.com
+1

Monitoring: RRD graph, SNMP, va tashqi monitoring (Zabbix/Nagios) orqali performance kuzatish.

11) Xavfsizlik va hardening tavsiyalari

GUI/SSH managementni faqat ishonchli tarmoqdan ruxsat eting.

Default port va accountlarni o‘zgartiring.

Admin uchun ikki faktorli autentifikatsiya (agar qo‘llab-quvvatlasa) yoki VPN orqali management qurilishini yoqing.

SSH accessni cheklash va password auth o‘rniga key-based auth ishlating.

Minimal paketlarni o‘rnating (keraksiz paketlar xujum sirtini oshiradi).

Regular update va patchlarni kuzating; security advisories uchun pfSense/Netgate bloglarini obuna bo‘ling. 
netgate.com

12) Tez-tez uchraydigan muammolar va yechimlar

Internet yo‘q / WAN down: gateway va DNS tekshiring, link-light va ISP cheklovlarini tekshiring.

Firewall qoida ishlamayapti: qoidalar tartibini tekshiring; NAT va firewall qoidalari o‘rtasidagi bog‘liqlikni yodda tuting (port forward yaratilganda avtomatik qoida paydo bo‘lishi mumkin yoki yo‘q).

Performance past: NIC offloading ni sozlang/tekshiring, CPU ko‘rsatkichlarini kuzating va kerak bo‘lsa hardware yangilang.

Packet loss on SPAN/TAP: monitoring uchun TAP tavsiya qilinadi; SPAN ba’zida packet drop olib keladi. (TAP haqida qaror qiling). 
pfsense.org

13) Amaliy checklist — o‘rnatishdan oldin va keyin

 Aparat/VM talablari aniqlandi.

 ISO/installer tayyor, checksum tekshirildi. 
pfsense.org

 Dastlabki LAN va WAN IP konfiguratsiyasi yaratilgan.

 Admin paroli va management huquqlari to‘g‘rilangan.

 Firewall qoidalari: minimaldan boshlanib, progessiv qoida testi o‘tkazildi.

 DHCP, DNS, VLAN va NAT sinovdan o‘tkazildi.

 VPN va remote access sinovlandi.

 Zaxira + update rejimi belgilandi.

 Monitoring va loglarni SIEM yoki tashqi tizimga yuborish rejasi.

14) Qo‘shimcha resurslar (rasmiy hujjatlar va qo‘llanmalar)

pfSense o‘rnatish va docs (rasmiy) — Install Walkthrough & Docs. 
docs.netgate.com
+1

pfSense download & release pages. 
pfsense.org
+1

High Availability recipes (rasmiy). 
docs.netgate.com

Amaliy blog/guide misollari va paket tavsiyalari (community blog misollari).

⭐ pfSense QANDAY ISHLATILADI (BATAFSIL QO‘LLANMA)
1️⃣ pfSense nima uchun ishlatiladi?

pfSense — bu FreeBSD asosidagi kuchli firewall va router. U quyidagi ishlar uchun qo‘llanadi:

Internetni NAT orqali taqsimlash

VLAN’lar bilan segmentatsiya qilish

Qoida asosida trafikni boshqarish

VPN o‘rnatish (OpenVPN, IPsec, WireGuard)

IDS/IPS (Suricata, Snort)

Load Balancing / Failover

Captive Portal (Wi-Fi login sahifasi)

2️⃣ pfSense o‘rnatilgandan keyin asosiy sozlamalar
📌 pfSense WEB INTERFACE kirish

Brauzer orqali:

https://192.168.1.1


login:

user: admin
pass: pfsense

3️⃣ pfSense INTERFACE (WAN & LAN) SOZLASH
🔹 WAN (Internet tomoni)

Internet provayderingiz bergan:

DHCP

Static IP

PPPoE

WAN → DHCP bo‘lsa, avtomatik IP oladi.

WAN → PPPoE bo‘lsa:
Interfaces → WAN → PPPoE login-parol kiritiladi.

🔹 LAN (Ichki tarmoq)

LAN standart IP:

192.168.1.1/24


Agar o‘zgartirmoqchi bo‘lsangiz:
Interfaces → LAN → Static IP

Masalan:

192.168.10.1/24

4️⃣ DHCP SERVER sozlash

Ko‘p ofislarda pfSense DHCP server o‘rni bo‘lib ishlaydi.

Services → DHCP Server → LAN

Masalan:

Range: 192.168.10.100 – 192.168.10.200
DNS: 192.168.10.1
Gateway: 192.168.10.1

5️⃣ INTERNET CHIQARISH QOIDALARI (Firewall Rules)

Har bir interface uchun qoidalar alohida bo‘ladi:

Firewall → Rules → LAN

Default qoida:

LAN to ANY — Allow


Demak LAN → Internet chiqishi ruxsat.

Agar cheklamoqchi bo‘lsangiz, masalan YouTube bloklash:
Firewall → Aliases → URL Table orqali blok ro‘yxat kiritasiz.

6️⃣ NAT SOZLAMALARI
🔹 Avtomatik NAT (tavsiya etiladi)

Firewall → NAT → Outbound

Automatic Outbound NAT tanlanadi

Bu holda LAN → WAN chiqishi avtomatik ishlaydi.

7️⃣ VLAN yaratish

Korxona uchun eng muhim bo‘lim.

Interfaces → Assignments → VLANs → Add

Misol:

Parent interface: LAN
VLAN tag: 10
Name: VLAN10


So‘ngra:
Interfaces → Assignments → Add VLAN10

IP berasiz:

192.168.10.1/24

8️⃣ VPN o‘rnatish (OpenVPN misolida)

VPN → OpenVPN → Wizards

Server Certificate yaratish

Tunnel network:

10.0.8.0/24


Client export paketi orqali .ovpn fayl beriladi

OpenVPN orqali xodimlar uydan ofisga ulana oladi.

9️⃣ IDS/IPS: Suricata yoki Snort
Suricata o‘rnatish:

System → Package Manager → Available Packages
— Suricata install

Keyin:
Services → Suricata

Interface:

WAN (IPS uchun)

LAN (Monitoring uchun)

Rules:

ET Open

Snort VRT

IPS rejimini yoqish:
IPS Mode → Enabled

1️⃣0️⃣ Traffic Shaping (QoS)

Masalan Zoom, Teams, VoIP uchun priority berish:

Firewall → Traffic Shaper → Wizards

Shablonlardan tanlasangiz bo‘ladi:

VoIP optimization

Gaming

Multi-WAN

1️⃣1️⃣ Load Balancing (2ta internet bo‘lsa)

System → Routing → Gateway Groups → Add

Masalan:

GW1 — Tier1
GW2 — Tier2


Bu Failover rejimi:
Internet 1 o‘chsa → Internet 2 ga o‘tadi.

1️⃣2️⃣ Captive Portal (Wi-Fi login sahifasi)

Services → Captive Portal → Add

Interface: LAN yoki Wi-Fi VLAN

Authentication: Local Database / RADIUS

Upload portal HTML page

Restoran, mehmonxona, universitetlar uchun juda qulay.

1️⃣3️⃣ Backup & Restore

Diagnostics → Backup/Restore

Har hafta backup olish tavsiya qilinadi.

1️⃣4️⃣ pfSense amaliy misollar
📌 1. Ofis uchun 3 ta VLAN

VLAN10 — Admin

VLAN20 — Xodimlar

VLAN30 — Mehmon Wi-Fi

Qoida:

VLAN10 → VLAN20 — Allow
VLAN20 → VLAN10 — Block
VLAN30 → ANY — Only Internet

📌 2. YouTube bloklash

Aliases → URL Table — YouTube domains import

Firewall Rule → Block → Apply

📌 3. O‘quv markazlarida Captive Portal

Parol bilan internet berish
Reklama banner qo‘yish
Limit qo‘yish (1 soat, 1Gb)

Xulosa

pfSense juda keng va professional darajali tizim. Uning eng ko‘p ishlatiladigan funksiyalari:

✔ Routing
✔ Firewall qoidalari
✔ NAT
✔ VLAN
✔ VPN
✔ IDS/IPS
✔ Captive Portal
✔ Load Balancing