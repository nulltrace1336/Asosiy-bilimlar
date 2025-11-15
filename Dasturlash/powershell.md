PowerShell Overview

PowerShell – bu Microsoft tomonidan yaratilgan komand-line shell va scripting tili bo‘lib, Windows tizimlari va boshqa platformalarda (Linux, macOS) tizimlarni avtomatlashtirish va boshqarish uchun ishlatiladi.

Asosiy xususiyatlari:

Cmdletlar: maxsus komandalar (misol: Get-Process, Set-Item).

Objektga asoslangan: PowerShell komandlarining chiqishi obyekt bo‘lib, string emas.

Pipeline: natijalarni keyingi komandaga yuborish (| operatori bilan).

Skriptlash: .ps1 fayllarda murakkab avtomatlashtirish yozish.

Remote Management: masofaviy kompyuterni boshqarish.

Oddiy misollar

```bash
# Hozirgi katalogdagi fayllarni ko'rsatish
Get-ChildItem

# Tizimdagi protsesslarni ko'rsatish
Get-Process

# Fayl yaratish va yozish
"Salom, PowerShell!" | Out-File -FilePath "C:\temp\hello.txt"

# Oddiy shartli sikl
for ($i=1; $i -le 5; $i++) {
    Write-Output "Qiymat: $i"
}
```

Foydali komandlar
| Komanda                | Maqsad                               |
|------------------------|--------------------------------------|
| Get-Help               | Komanda haqida yordam                |
| Get-Command            | Tizimdagi barcha komandlarni ko‘rsatish |
| Set-ExecutionPolicy    | Skript ishga tushirish siyosatini sozlash |
| Get-Process            | Ishlayotgan jarayonlarni ko‘rsatish  |
| Stop-Process           | Jarayonni to‘xtatish                 |
