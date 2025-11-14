## Firewall – Misollar
Linux UFW

```bash
sudo ufw enable
sudo ufw allow 22
sudo ufw deny 80
```

Windows Firewall

```bash
New-NetFirewallRule -DisplayName "Block80" -Direction Inbound -LocalPort 80 -Protocol TCP -Action Block
```