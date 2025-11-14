## Active Directory – User yaratish

```bash
New-ADUser -Name "Behruz" -AccountPassword (ConvertTo-SecureString "Parol123!" -AsPlainText -Force) -Enabled $true
```