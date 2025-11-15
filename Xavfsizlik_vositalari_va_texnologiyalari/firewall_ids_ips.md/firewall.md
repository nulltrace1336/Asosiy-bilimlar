🔥 Firewalld — Batafsil Qo‘llanma

Firewalld — Linux tizimlarida (CentOS, RHEL, Fedora) ishlaydigan zamonaviy, dinamik firewall boshqaruv tizimi. U iptables’dan farqli o‘laroq, qoidalarni tizimni qayta yuklamasdan (restart qilmasdan) qo‘llash imkonini beradi.

🧩 Firewalld Asoslari
🔹 Zones (zonalar)

Firewalld tarmoqlarni xavfsizlik bo‘yicha zonalarga ajratadi. Har bir zona o‘ziga xos qoidalarga ega.

Eng ko‘p ishlatiladigan zonalar:

| Zona         | Tavsifi                                      |
| ------------ | -------------------------------------------- |
| **public**   | Tashqi tarmoqlar uchun, minimal ruxsatlar    |
| **home**     | Uy tarmoqlari, biroz kengroq ruxsatlar       |
| **internal** | Ishonchli ichki tarmoq                       |
| **dmz**      | Internetdan kirishga mo‘ljallangan serverlar |
| **trusted**  | To‘liq ruxsat berilgan (eng xavfli)          |
| **drop**     | Barcha trafikni tashlaydi                    |
| **block**    | So‘rovlarni rad qiladi (ICMP xato qaytaradi) |

🔹 Services

HTTP, HTTPS, SSH kabi xizmatlar tayyor profillarga ega.

🔹 Rich Rules

Advanced qoidalar:

Source IP bilan filtr

Port + protocol

Logging

Masquerade / NAT

🟦 Firewalld’ni Tekshirish
```bash
sudo systemctl status firewalld
```

Ishlatish:

```bash
sudo systemctl start firewalld
sudo systemctl enable firewalld
```
🟧 Zonalar bilan ishlash
Barcha zonalarni ko‘rish:
```bash
firewall-cmd --get-zones
```
Faol zona:
```bash
firewall-cmd --get-active-zones
```
Zona tafsilotini ko‘rish:
```bash
firewall-cmd --zone=public --list-all
```
🟩 Port va Servicelar bilan ishlash
🔸 Port ochish:
```bash
firewall-cmd --zone=public --add-port=8080/tcp
```

Doimiy (reloaddan so‘ng ham saqlanadi):

```bash
firewall-cmd --zone=public --add-port=8080/tcp --permanent
firewall-cmd --reload
```
🔸 Port yopish:
```bash
firewall-cmd --zone=public --remove-port=8080/tcp --permanent
firewall-cmd --reload
```
🔸 Xizmatlarni ruxsat berish:
```bash
firewall-cmd --zone=public --add-service=http --permanent
firewall-cmd --reload
```

Xizmatni o‘chirish:
```bash
firewall-cmd --zone=public --remove-service=http --permanent
```
🟥 Rich Rules — Advanced Qoidalar
🔸 IP manzildan kirishni bloklash
```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="192.168.1.10" reject'
```
🔸 Faqat bitta IPga ruxsat berish (white-list)
```bash
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="1.2.3.4" port port="22" protocol="tcp" accept'
```
🔸 Ma'lum portga kirishni loglash
```bash
firewall-cmd --permanent --add-rich-rule='rule port port="22" protocol="tcp" log prefix="SSH Attempt: " level="info"'
```
🔸 NAT / Masquerade yoqish (Internet sharing)
```bash
firewall-cmd --zone=public --add-masquerade --permanent
```
🟪 Interfeyslarni zonalarga bog‘lash
```bash
firewall-cmd --zone=home --change-interface=eth0 --permanent
firewall-cmd --reload
```

Interfeys qaysi zonada:
```bash
firewall-cmd --get-active-zones
```
🟫 Firewalld konfiguratsiyasini backup & restore

Backup:
```bash
cp -r /etc/firewalld /etc/firewalld-backup
```

Restore:
```bash
rm -r /etc/firewalld
mv /etc/firewalld-backup /etc/firewalld
systemctl restart firewalld
```
🟨 Firewalld vs Iptables
Xususiyat	Firewalld	Iptables
Dynamic rules	✔	✖
Zone-based	✔	✖
Reloadsiz qoida	✔	✖
GUI	✔	✖
Performance	Juda yaxshi	Yaxshi
🟦 Eng ko‘p ishlatiladigan buyruqlar
```bash
firewall-cmd --state
firewall-cmd --reload
firewall-cmd --list-all
firewall-cmd --list-ports
firewall-cmd --list-services
```
🎯 Xulosa

Firewalld juda qulay:

Tizimni to‘xtatmasdan firewall o‘rnatish mumkin

Zonalarga bo‘lingan

Rich rules bilan kuchli filtrlar

NAT, port forwarding, logging — barchasi bor