FortiGate — nima va qanday ishlatiladi (batafsil, amaliy)

Quyida FortiGate (Fortinet) NGFW/UTM qurilmasini qadam-bqadam qanday ishlatish, eng muhim komponentlar, amaliy CLI/GUI misollar, HA/VPN/SD-WAN/UTM funksiyalari, log/monitoring va best-practice’lar — hammasi aniq va amaliy tarzda.

Qisqacha: FortiGate — Fortinet’ning NGFW/UTM yechimi; tarmoqni himoya qilish uchun firewall, IPS, antivirus, web-filter, VPN, SD-WAN va FortiGuard threat-intel xizmatlarini birlashtiradi. 
Fortinet

1. Asosiy tushunchalar va komponentlar

Interfaces/Zonelar: fiziк/virtual (vdom) interfeyslar, zone-based yoki single-interface policy ishlatish mumkin.

Security Policies: trafikni ruxsat/cheklash uchun Policy & Objects → Firewall Policy (GUI) yoki config firewall policy (CLI).

NAT / Virtual IP (VIP): internetdan ichki serverga yo‘naltirish (DNAT) yoki ichki manzildan internetga chiqishda SNAT (source nat). 
Fortinet Documentation

UTM xizmatlari: IPS, Antivirus, Web Filtering, Application Control, Anti-Spam, SSL Inspection — FortiGuard bilan yangilanadi. 
kevindarian.com

Management: GUI (Web UI), CLI (SSH), FortiManager (mass config), FortiAnalyzer (log/analytics). 
Fortinet Documentation
+1

2. Boshlang‘ich qo‘yish (Quick start)

Fizik/VM o‘rnatish → management IP belgilang.

Web GUI ga kiring: https://<FGT_IP> (admin/login).

Interfaces → WAN/LAN sozlang (static/DHCP/PPPoE).

Basic firewall policy yarating: LAN → ANY — Allow (test uchun qisqa vaqt).

DHCP, DNS, va kerakli NAT qo‘llanmalarini sozlang.

3. Firewall policy (amaliy misol)

GUI: Policy & Objects → IPv4 Policy → Create New
CLI misol (oddiy LAN → WAN ruxsat):
```bash
config firewall policy
    edit 1
        set name "LAN-TO-WAN"
        set srcintf "lan"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
```

Eslatma: FortiGate’da policylari yuqoridan pastga ishlaydi — mos kelgan birinchi policy amal qiladi.

4. NAT va Virtual IP (DNAT) misoli

Interfeysda tashqi IPni ichki web serverga yo‘naltirish (GUI: Policy & Objects → Virtual IPs):
CLI misol:
```bash
config firewall vip
    edit "VIP-web"
        set extip 203.0.113.10
        set mappedip 192.168.10.10
    next
end

config firewall policy
    edit 10
        set name "WAN-to-WEB"
        set srcintf "wan1"
        set dstintf "dmz"
        set srcaddr "all"
        set dstaddr "VIP-web"
        set action accept
        set schedule "always"
        set service "HTTP"
    next
end
```

(haqiqiy misollarda portlar, logging va security profiles qo‘shing). 
Fortinet Documentation

5. IPsec site-to-site VPN (soddalashtirilgan qadamlar)

FortiOS GUI wizard yoki CLI bilan. Rasmiy qo‘llanma misollari mavjud. 
Fortinet Documentation
+1

CLI qisqacha:
```bash
config vpn ipsec phase1-interface
    edit "to-branch"
        set interface "wan1"
        set remote-gw 198.51.100.2
        set psksecret YOUR_PSK
        set proposal aes256-sha256
    next
end

config vpn ipsec phase2-interface
    edit "to-branch-p2"
        set phase1name "to-branch"
        set proposal aes256-sha256
        set dst-subnet 10.1.0.0/24
        set src-subnet 10.0.0.0/24
    next
end
```

So‘ngra security policy va static route yoki tunnel route qo‘shing. 
Fortinet Documentation

6. SSL VPN (remote access) — tez qadamlar

VPN → SSL-VPN → Portal yarating (tunnel mode yoki web mode).

User/Group va Local User yoki LDAP/Radius sozlang.

Policy: SSLVPN → Internal resources ga access berish.

FortiClient bilan to‘liq tunnel yoki veb-portal orqali kirish. 
Fortinet Documentation

7. High Availability (HA) — Active-Passive

FortiGate HA yordamida Active/Passive cluster yaratish mumkin: VLAN/kabel heartbeat, session sync va konfiguratsiya sync o‘rnatiladi. GUI yoki CLI orqali HA sozlanadi. 
Fortinet Documentation
+1

Qisqacha CLI start:
```bash
config system ha
    set mode a-p
    set group-name "FGT-HA"
    set password "ha-password"
    set hbdev "port2" 50
end
```

(haqiqiy implementatsiyada HA link’lar, override priority, monitor interface’lar va failover testlarni rejalashtiring).

8. SD-WAN (multiple WAN management)

FortiGate SD-WAN: bir nechta Internet linklarni birlashtirib, monitoring, path selection va application steering orqali trafikni yo‘naltiradi. SD-WAN qoidalari va SLAs asosida failover va load-balancing ta’minlanadi. 
Fortinet Documentation
+1

9. UTM (IPS / AV / Webfilter / Application Control)

IPS (signature/heuristic) — tarmoq hodisalarini bloklash/alert.

Antivirus / FortiSandbox — fayl tahlili va deteksiyalar.

Web Filter (FortiGuard) — kategoriyalar bo‘yicha bloklash va URL reputatsiyasi.

SSL Inspection — shifrlangan trafikni tekshirish (man-in-the-middle sertifikatlar bilan).
Ushbu profilni security policy’ga qo‘shasiz (Profiles → Create → Attach to Policy). 
kevindarian.com

10. Logging, monitoring va analytics

Local logs va FortiAnalyzer ga yuborish — analytics va long-term retention uchun kerak. FortiManager — markaziy konfiguratsiya/firmware boshqaruvi. 
Fortinet Documentation
+1

Logging best practices: barcha policylar uchun log traffic yoqing, FortiAnalyzer yoki SIEM'ga yuboring, RRD grafiklar va health monitoring o‘rnatilsin.

11. CLI foydali buyruqlar (tezkor troubleshooting)

get system status — umumiy holat.

diagnose sys top — protsesslar.

diagnose debug enable va diagnose debug flow filter — traffic debugging (ehtiyotkorlik bilan).

get system performance top — resurslar.

diagnose vpn ike gateway / diagnose vpn tunnel list — VPN holati.

execute ha manage <unit> va get system ha status — HA holati.

12. Firmware, licensing va FortiGuard

Firmware (FortiOS) yangilanishlari: release notes o‘qib, backup qilib, maintenance window’da yangilang.

FortiGuard litsenziyalari: AV, IPS, Webfilter, Sandbox, threat intel — yangilanish va full protection uchun kerak.

Model va throughput (NGFW feature’lari) vendor dokumentatsiyasiga qarab tanlanadi. 
Fortinet
+1

13. Best-practice checklist (amalga oshirishdan oldin)

 Management access faqat ishonchli manbalar (VPN yoki management VLAN).

 Barcha policylar uchun logging yoqilgan.

 Least-privilege principe: faqat kerakli port/protokollar ruxsat.

 SSL inspection uchun sertifikat strategiyasi tayyor.

 Backup va firmware upgrade rejasi (backup oldin).

 HA va failover testlari rejalashtirilgan.

 FortiAnalyzer / FortiManager integratsiyasi (agar ko‘p device bo‘lsa). 
Fortinet Documentation
+1

14. Resurslar (rasmiy qo‘llanmalar / tutoriallar)

FortiGate overview & NGFW: Fortinet docs. 
Fortinet

IPsec site-to-site step-by-step: Fortinet docs. 
Fortinet Documentation

SSL VPN (tunnel mode) example: Fortinet docs. 
Fortinet Documentation

HA setup guide: Fortinet docs. 
Fortinet Documentation

SD-WAN overview & deployment: Fortinet docs & guides.