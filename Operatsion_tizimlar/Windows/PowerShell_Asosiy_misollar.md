## PowerShell – Asosiy misollar

Servislarni ko‘rish:

```bash
Get-Service
```

Port skan qilish:
```bash
Test-NetConnection -ComputerName 192.168.1.10 -Port 3389
```

Fayl yaratish:
```bash
New-Item -Path "C:\logs\test.txt" -ItemType File
```