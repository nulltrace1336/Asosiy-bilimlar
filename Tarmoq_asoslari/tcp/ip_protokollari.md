# TCP/IP Protokollari – Misollar

## Ping va Traceroute orqali tarmoq diagnostikasi

Tarmoqga ulanishingizni tekshirish va paket yo‘lini aniqlash uchun quyidagi buyruqlardan foydalaning:

```bash
# Ping orqali saytga ulanishni tekshirish
ping google.com

# Traceroute orqali paket yo‘lini aniqlash
# Linux
traceroute google.com
# Windows
tracert google.com

TCP port tekshirish

SSH yoki boshqa servis porti ochiq-yo‘qligini tekshirish:

nc -zv 192.168.1.10 22  # Bu buyruq 22-port (SSH) ochiqmi tekshiradi
