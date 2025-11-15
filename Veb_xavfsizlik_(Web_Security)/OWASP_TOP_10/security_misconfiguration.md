Security Misconfiguration - Batafsil Ma'lumot
Nima bu?
Security Misconfiguration - bu tizim, server, database yoki application'ni noto'g'ri sozlash natijasida yuzaga keladigan xavfsizlik zaifligidir. OWASP Top 10 (2021) ro'yxatida #5 o'rinda turadi.
Bu eng keng tarqalgan zaifliklardan biri, chunko tizimni xavfsiz sozlash murakkab va ko'p qadamlarni talab qiladi.
Asosiy Muammolar
1. Default Configurations

Default parollar
Default portlar
Sample applications o'chirilmagan

2. Unnecessary Features Enabled

Keraksiz servislar ishlamoqda
Debug mode production'da
Directory listing yoqilgan

3. Missing Security Headers

HSTS yo'q
CSP yo'q
X-Frame-Options yo'q

4. Outdated Software

Eski versiyalar
Patch qilinmagan sistemalar
EOL (End of Life) software

5. Error Messages

Stack trace ko'rsatiladi
Detailed error messages
Database errors ochiq

Keng Tarqalgan Xatolar
❌ 1. Default Credentials
bash# Juda keng tarqalgan default parollar
MongoDB: admin / admin
MySQL: root / (bo'sh parol)
PostgreSQL: postgres / postgres
Redis: (parolsiz)
Tomcat: admin / admin
Jenkins: admin / password

# Router va IoT qurilmalar
admin / admin
admin / password
admin / 1234
root / root

# HAQIQIY MISOLLAR:
# 2017 - Equifax breach: Default admin credentials
# 2016 - Mirai botnet: IoT devices default passwords
❌ 2. Debug Mode Production'da
python# ❌ DJANGO - DEBUG MODE
# settings.py
DEBUG = True  # ❌ PRODUCTION'DA HECH QACHON!
ALLOWED_HOSTS = ['*']  # ❌ Hammaga ochiq

# Debug mode yoqilganda:
# - Stack trace ko'rsatiladi
# - Source code ko'rinadi
# - SQL query'lar ko'rinadi
# - Environment variables ko'rinadi
javascript// ❌ NODE.JS - Detailed errors
app.use((err, req, res, next) => {
    res.status(500).json({
        error: err.message,
        stack: err.stack,  // ❌ Stack trace
        details: err       // ❌ Full error object
    });
});
✅ TO'G'RI KONFIGURATSIYA:
python# ✅ DJANGO - PRODUCTION
import os

DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']

# Custom error pages
ADMINS = [('Admin', 'admin@yourdomain.com')]
LOGGING = {
    'version': 1,
    'handlers': {
        'file': {
            'level': 'ERROR',
            'class': 'logging.FileHandler',
            'filename': '/var/log/django/error.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'ERROR',
            'propagate': True,
        },
    },
}
javascript// ✅ NODE.JS - Production error handling
if (process.env.NODE_ENV === 'production') {
    app.use((err, req, res, next) => {
        // Error'ni log qilish
        console.error(err.stack);
        logger.error({
            message: err.message,
            stack: err.stack,
            url: req.url,
            method: req.method,
            ip: req.ip
        });
        
        // Foydalanuvchiga umumiy xabar
        res.status(500).json({
            error: 'Internal server error'
        });
    });
} else {
    // Development'da batafsil
    app.use((err, req, res, next) => {
        res.status(500).json({
            error: err.message,
            stack: err.stack
        });
    });
}
❌ 3. Directory Listing
nginx# ❌ NGINX - Directory listing yoqilgan
location /uploads {
    autoindex on;  # ❌ Fayllar ro'yxati ko'rinadi
}

# Hujumchi ko'ra oladi:
# https://example.com/uploads/
# - user_photos/
# - documents/
# - backups/
✅ TO'G'RI:
nginx# ✅ NGINX - Directory listing o'chirilgan
location /uploads {
    autoindex off;
}

# Yoki butunlay block qilish
location ~ /\.git {
    deny all;
}

location ~ /\.env {
    deny all;
}

location ~ /backup {
    deny all;
}
❌ 4. Unnecessary Services
bash# ❌ Keraksiz servislar ishlamoqda
sudo netstat -tuln

# Misol output:
Proto Recv-Q Send-Q Local Address   State
tcp   0      0      0.0.0.0:21      LISTEN  # FTP
tcp   0      0      0.0.0.0:23      LISTEN  # Telnet
tcp   0      0      0.0.0.0:3306    LISTEN  # MySQL (public)
tcp   0      0      0.0.0.0:6379    LISTEN  # Redis (public)
tcp   0      0      0.0.0.0:8080    LISTEN  # Debug panel
✅ TO'G'RI:
bash# ✅ Keraksiz servislarni o'chirish
sudo systemctl stop telnet
sudo systemctl disable telnet

# ✅ Servislarni faqat localhost'da ishlatish
# Redis config
bind 127.0.0.1

# MySQL config
bind-address = 127.0.0.1

# ✅ Firewall bilan himoya
sudo ufw deny 3306  # MySQL external access
sudo ufw allow from 10.0.0.0/8 to any port 3306  # Faqat internal
❌ 5. Missing Security Headers
javascript// ❌ Security headers yo'q
app.get('/', (req, res) => {
    res.send('Hello World');
});

// Natija: Barcha security headers yo'q
// - No HSTS
// - No CSP
// - No X-Frame-Options
// - etc.
✅ TO'G'RI:
javascript// ✅ Helmet.js ishlatish
const helmet = require('helmet');

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    },
    frameguard: {
        action: 'deny'
    },
    noSniff: true,
    xssFilter: true,
    referrerPolicy: {
        policy: 'strict-origin-when-cross-origin'
    }
}));
python# ✅ Flask - Security headers
from flask import Flask, make_response

@app.after_request
def add_security_headers(response):
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response
nginx# ✅ NGINX - Headers
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Server version yashirish
server_tokens off;
❌ 6. Cloud Storage Misconfiguration
bash# ❌ AWS S3 Bucket - Public access
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::my-bucket/*"
        }
    ]
}

# MASHHUR BREACHES:
# - Capital One (2019) - S3 misconfiguration
# - Accenture (2017) - Public S3 buckets
# - Verizon (2017) - 14M customer records
✅ TO'G'RI:
json{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::123456789:user/specific-user"
            },
            "Action": [
                "s3:GetObject",
                "s3:PutObject"
            ],
            "Resource": "arn:aws:s3:::my-bucket/*",
            "Condition": {
                "IpAddress": {
                    "aws:SourceIp": "203.0.113.0/24"
                }
            }
        }
    ]
}
bash# ✅ S3 Bucket hardening
aws s3api put-public-access-block \
    --bucket my-bucket \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Encryption yoqish
aws s3api put-bucket-encryption \
    --bucket my-bucket \
    --server-side-encryption-configuration \
    '{"Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]}'

# Versioning
aws s3api put-bucket-versioning \
    --bucket my-bucket \
    --versioning-configuration Status=Enabled

# Logging
aws s3api put-bucket-logging \
    --bucket my-bucket \
    --bucket-logging-status \
    '{"LoggingEnabled": {"TargetBucket": "my-logs-bucket", "TargetPrefix": "s3-logs/"}}'
❌ 7. Database Misconfiguration
bash# ❌ MongoDB - Authentication yo'q
# mongod.conf
net:
  bindIp: 0.0.0.0  # ❌ Hammaga ochiq
security:
  authorization: disabled  # ❌ Auth yo'q

# ❌ Redis - Parolsiz
# redis.conf
bind 0.0.0.0  # ❌ Public
# requirepass yo'q

# ❌ MySQL - Root remote access
mysql> CREATE USER 'root'@'%' IDENTIFIED BY 'password';
# ❌ Istalgan joydan root kirishi mumkin
✅ TO'G'RI:
yaml# ✅ MongoDB - Xavfsiz konfiguratsiya
# mongod.conf
net:
  bindIp: 127.0.0.1
  port: 27017

security:
  authorization: enabled

# Admin yaratish
use admin
db.createUser({
  user: "admin",
  pwd: passwordPrompt(),
  roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
})

# Application user (limited permissions)
use myapp
db.createUser({
  user: "app_user",
  pwd: passwordPrompt(),
  roles: [ { role: "readWrite", db: "myapp" } ]
})
conf# ✅ Redis - Xavfsiz
bind 127.0.0.1
protected-mode yes
requirepass VeryStrongPassword123!@#
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
maxmemory 256mb
maxmemory-policy allkeys-lru

# TLS/SSL
port 0
tls-port 6379
tls-cert-file /path/to/redis.crt
tls-key-file /path/to/redis.key
tls-ca-cert-file /path/to/ca.crt
sql-- ✅ MySQL - Xavfsiz
-- Root faqat localhost
CREATE USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword123!';

-- Application user limited
CREATE USER 'app_user'@'10.0.0.%' IDENTIFIED BY 'AppPassword123!';
GRANT SELECT, INSERT, UPDATE, DELETE ON myapp.* TO 'app_user'@'10.0.0.%';

-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove test database
DROP DATABASE IF EXISTS test;

-- Disable LOAD DATA LOCAL INFILE
SET GLOBAL local_infile = 0;

FLUSH PRIVILEGES;
❌ 8. CORS Misconfiguration
javascript// ❌ Har kimga ruxsat
app.use(cors({
    origin: '*',  // ❌ Barcha domenlar
    credentials: true  // ❌ Credentials bilan
}));

// Bu XSS va CSRF hujumlariga ochiq!
✅ TO'G'RI:
javascript// ✅ Whitelist approach
const allowedOrigins = [
    'https://yourdomain.com',
    'https://www.yourdomain.com',
    'https://app.yourdomain.com'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, curl, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) === -1) {
            const msg = 'CORS policy does not allow access from this origin.';
            return callback(new Error(msg), false);
        }
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Range', 'X-Content-Range'],
    maxAge: 600  // 10 minutes
}));
❌ 9. SSL/TLS Misconfiguration
nginx# ❌ Zaif SSL konfiguratsiya
server {
    listen 443 ssl;
    
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;  # ❌ Eski protokollar
    ssl_ciphers ALL;  # ❌ Zaif cipher'lar
    ssl_prefer_server_ciphers off;
}
✅ TO'G'RI:
nginx# ✅ Qattiq SSL/TLS konfiguratsiya
server {
    listen 443 ssl http2;
    server_name example.com;
    
    # Modern protocols only
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Strong ciphers
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers on;
    
    # Certificates
    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;
    ssl_trusted_certificate /etc/letsencrypt/live/example.com/chain.pem;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;
    
    # Session settings
    ssl_session_cache shared:SSL:50m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    
    # DH parameters
    ssl_dhparam /etc/nginx/dhparam.pem;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name example.com;
    return 301 https://$server_name$request_uri;
}
❌ 10. Logging Misconfiguration
python# ❌ Sensitive data log'da
import logging

logging.basicConfig(level=logging.DEBUG)

def login(username, password):
    logging.debug(f"Login attempt: {username}:{password}")  # ❌ Parol!
    
def process_payment(card_number, cvv):
    logging.info(f"Payment with card: {card_number}, CVV: {cvv}")  # ❌ Card data!
✅ TO'G'RI:
python# ✅ Sanitized logging
import logging
import re

class SensitiveDataFilter(logging.Filter):
    def filter(self, record):
        # Parollarni mask qilish
        record.msg = re.sub(
            r'password["\s:=]+[\w\d]+',
            'password=***REDACTED***',
            str(record.msg),
            flags=re.IGNORECASE
        )
        
        # Kredit kartalarni mask qilish
        record.msg = re.sub(
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'XXXX-XXXX-XXXX-XXXX',
            str(record.msg)
        )
        
        # Email'larni qisman mask qilish
        record.msg = re.sub(
            r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            lambda m: f"{m.group(1)[:3]}***@{m.group(2)}",
            str(record.msg)
        )
        
        return True

# Logger sozlash
logger = logging.getLogger(__name__)
logger.addFilter(SensitiveDataFilter())

def login(username, password):
    logger.info(f"Login attempt for user: {username}")  # ✅ Parol yo'q
    
def process_payment(card_number, cvv):
    masked_card = f"****-****-****-{card_number[-4:]}"
    logger.info(f"Payment processed with card ending: {card_number[-4:]}")  # ✅ Masked
Server Hardening Checklist
🔒 Operating System
bash# ✅ System updates
sudo apt update && sudo apt upgrade -y

# ✅ Automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades

# ✅ Firewall
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# ✅ Fail2ban (brute force himoya)
sudo apt install fail2ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# ✅ Disable root login
sudo passwd -l root

# ✅ SSH hardening
# /etc/ssh/sshd_config
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
Protocol 2
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2

sudo systemctl restart sshd

# ✅ Remove unnecessary packages
sudo apt autoremove
sudo apt purge telnet ftp
🔒 Web Server (Nginx)
nginx# ✅ nginx.conf hardening
user www-data;
worker_processes auto;
pid /run/nginx.pid;

# Hide version
server_tokens off;

# Limits
client_body_buffer_size 1K;
client_header_buffer_size 1k;
client_max_body_size 10m;
large_client_header_buffers 2 1k;

# Timeouts
client_body_timeout 10;
client_header_timeout 10;
keepalive_timeout 5 5;
send_timeout 10;

# Rate limiting
limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
limit_req zone=one burst=5;

# File upload restrictions
location ~ \.(php|jsp|asp)$ {
    deny all;
}

# Block access to hidden files
location ~ /\. {
    deny all;
    access_log off;
    log_not_found off;
}
🔒 Application
python# ✅ Django security settings
# settings.py

# HTTPS
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True

# HSTS
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Other security
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_BROWSER_XSS_FILTER = True
X_FRAME_OPTIONS = 'DENY'

# Session security
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Strict'
SESSION_COOKIE_AGE = 3600  # 1 hour

# CSRF
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Strict'

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator', 'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

# Allowed hosts
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']

# Debug
DEBUG = False
ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')
Docker Security
dockerfile# ✅ Secure Dockerfile
FROM node:18-alpine

# Non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Working directory
WORKDIR /app

# Dependencies
COPY package*.json ./
RUN npm ci --only=production && \
    npm cache clean --force

# Application code
COPY --chown=nodejs:nodejs . .

# Switch to non-root
USER nodejs

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node healthcheck.js

# Expose port
EXPOSE 3000

CMD ["node", "index.js"]
yaml# ✅ docker-compose.yml security
version: '3.8'

services:
  app:
    image: myapp:latest
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    tmpfs:
      - /tmp
    environment:
      - NODE_ENV=production
    secrets:
      - db_password
      - api_key

secrets:
  db_password:
    external: true
  api_key:
    external: true
Security Scanning Tools
bash# ✅ SSL/TLS test
nmap --script ssl-enum-ciphers -p 443 example.com
testssl.sh https://example.com

# ✅ Web server test
nikto -h https://example.com

# ✅ Dependency vulnerabilities
npm audit
pip-audit
snyk test

# ✅ Docker image scan
docker scan myapp:latest
trivy image myapp:latest

# ✅ Infrastructure scan
nmap -sV -sC example.com
openvas

# ✅ Configuration scan
lynis audit system
Monitoring va Alerting
python# ✅ Security event monitoring
import logging
from datetime import datetime

class SecurityMonitor:
    def __init__(self):
        self.logger = logging.getLogger('security')
    
    def log_failed_login(self, username, ip):
        self.logger.warning(f"Failed login: {username} from {ip}")
        
        # Check for brute force
        recent_failures = self.get_recent_failures(ip)
        if recent_failures > 5:
            self.alert_admin(f"Possible brute force from {ip}")
            self.block_ip(ip)
    
    def log_privilege_escalation(self, user, action):
        self.logger.critical(f"Privilege escalation attempt: {user} tried {action}")
        self.alert_admin(f"CRITICAL: Privilege escalation by {user}")
    
    def log_data_access(self, user, resource):
        self.logger.info(f"Data access: {user} accessed {resource}")
        
        # Detect unusual patterns
        if self.is_unusual_access(user, resource):
            self.alert_admin(f"Unusual access pattern: {user} -> {resource}")
Best Practices Summary
✅ QILING:

Regular updates - tizim va dependencies
Principle of least privilege - minimal ruxsatlar
Security headers - barcha muhim headerlar
Strong authentication - qattiq parollar, 2FA
Encryption - at rest va in transit
Logging va monitoring - barcha security events
Regular security audits
Automated scanning - CI/CD'da
Configuration management - IaC (Infrastructure as Code)
Incident response plan

❌ QILMANG:

Default credentials qoldirish
Debug mode production'da
Unnecessary services ishlatish
Outdated software
Missing security headers
Weak SSL/TLS
Public cloud storage
Sensitive data log'larda
Overly permissive CORS
No monitoring/alerting