Injection - Batafsil Ma'lumot
Nima bu?
Injection - bu hujumchi o'z kodini yoki buyruqlarini application'ga yuborib, tizimni o'z maqsadida ishlatishi. OWASP Top 10 (2021) ro'yxatida #3 o'rinda turadi.
Injection hujumlari eng xavfli va keng tarqalgan zaifliklardan biri. Ular orqali:

Ma'lumotlar bazasini o'chirish mumkin
Barcha ma'lumotlarni o'g'irlash mumkin
Server'ni to'liq nazorat qilish mumkin
Fayllarni o'qish/yozish mumkin

Injection Turlari
1. SQL Injection (Eng keng tarqalgan)
2. NoSQL Injection
3. OS Command Injection
4. LDAP Injection
5. XPath Injection
6. Expression Language (EL) Injection
7. Server-Side Template Injection (SSTI)
8. Log Injection

1. SQL Injection (SQLi)
❌ Xavfli Kod
python# ❌ PYTHON - String concatenation
username = request.form['username']
password = request.form['password']

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

# HUJUM:
# username: admin'--
# password: anything
# NATIJA: SELECT * FROM users WHERE username='admin'--' AND password='anything'
# '--' SQL'da comment, parol tekshirilmaydi!
php// ❌ PHP - Direct concatenation
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($conn, $query);

// HUJUM:
// username: ' OR '1'='1
// password: ' OR '1'='1
// NATIJA: SELECT * FROM users WHERE username='' OR '1'='1' AND password='' OR '1'='1'
// Har doim TRUE!
javascript// ❌ NODE.JS - String interpolation
const username = req.body.username;
const query = `SELECT * FROM users WHERE username = '${username}'`;

db.query(query, (err, results) => {
    // ...
});

// HUJUM:
// username: admin'; DROP TABLE users; --
// NATIJA: SELECT * FROM users WHERE username = 'admin'; DROP TABLE users; --'
// Ma'lumotlar bazasi o'chiriladi!
✅ Xavfsiz Kod (Prepared Statements)
python# ✅ PYTHON - Parameterized query (PyMySQL)
username = request.form['username']
password = request.form['password']

query = "SELECT * FROM users WHERE username=%s AND password=%s"
cursor.execute(query, (username, password))

# Yoki psycopg2 (PostgreSQL)
query = "SELECT * FROM users WHERE username=%s AND password=%s"
cursor.execute(query, [username, password])

# Yoki SQLAlchemy (ORM)
from sqlalchemy import text

stmt = text("SELECT * FROM users WHERE username=:username AND password=:password")
result = session.execute(stmt, {"username": username, "password": password})
php// ✅ PHP - Prepared statements (MySQLi)
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $conn->prepare("SELECT * FROM users WHERE username=? AND password=?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

// Yoki PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE username=:username AND password=:password");
$stmt->execute(['username' => $username, 'password' => $password]);
$result = $stmt->fetchAll();
javascript// ✅ NODE.JS - Prepared statements
const mysql = require('mysql2/promise');

const username = req.body.username;
const [rows] = await connection.execute(
    'SELECT * FROM users WHERE username = ?',
    [username]
);

// Yoki Sequelize (ORM)
const users = await User.findAll({
    where: {
        username: username
    }
});

// Yoki Knex.js
const users = await knex('users')
    .where('username', username)
    .select('*');
SQL Injection Turlari
A. Classic SQLi (In-band)
sql-- Union-based
' UNION SELECT null, username, password, null FROM users--

-- Error-based
' AND 1=CONVERT(int, (SELECT @@version))--

-- Boolean-based
' AND 1=1--  (TRUE - sahifa normal)
' AND 1=2--  (FALSE - xato yoki boshqa natija)
B. Blind SQLi
python# ❌ Xavfli kod
user_id = request.args.get('id')
query = f"SELECT * FROM users WHERE id={user_id}"
result = cursor.execute(query)

if result:
    return "User exists"
else:
    return "User not found"

# HUJUM (Boolean-based blind):
# id=1 AND (SELECT LENGTH(password) FROM users WHERE username='admin')=8--
# TRUE bo'lsa, parol uzunligi 8
# Har bir belgini taxmin qilish:
# id=1 AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
C. Time-based Blind SQLi
sql-- MySQL
' AND IF(1=1, SLEEP(5), 0)--
' AND IF((SELECT LENGTH(password) FROM users WHERE username='admin')=8, SLEEP(5), 0)--

-- PostgreSQL
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- MSSQL
'; WAITFOR DELAY '00:00:05'--
D. Second Order SQLi
python# ❌ Registration
username = "admin'--"
insert_query = f"INSERT INTO users (username) VALUES ('{username}')"
# Database'ga saqlanadi: admin'--

# ❌ Keyinchalik ishlatiladigan qism
username = get_username_from_session()  # admin'--
query = f"SELECT * FROM posts WHERE author='{username}'"
# NATIJA: SELECT * FROM posts WHERE author='admin'--'
# Comment qismi boshqa qismni o'chiradi
SQL Injection Detection
python# ✅ Input validation
import re

def is_sql_injection_attempt(input_string):
    """SQL injection pattern'larni aniqlash"""
    
    # Xavfli pattern'lar
    patterns = [
        r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|#|\/\*|\*\/)",  # SQL comments
        r"(\bOR\b|\bAND\b).*?=.*?",  # OR 1=1
        r"(\';|\";)",  # Quote escape
        r"(\bSLEEP\b|\bWAITFOR\b|\bBENCHMARK\b)",  # Time-based
        r"(\bxp_cmdshell\b|\bxp_regread\b)",  # MSSQL functions
    ]
    
    for pattern in patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    
    return False

# Ishlatish
username = request.form['username']
if is_sql_injection_attempt(username):
    log_security_event("SQL injection attempt", username)
    abort(400, "Invalid input")

2. NoSQL Injection
❌ Xavfli Kod (MongoDB)
javascript// ❌ NODE.JS - Direct object injection
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Username va password to'g'ridan-to'g'ri query'ga
    db.collection('users').findOne({
        username: username,
        password: password
    }, (err, user) => {
        if (user) {
            res.json({ success: true });
        }
    });
});

// HUJUM:
// POST /login
// {
//   "username": {"$ne": null},
//   "password": {"$ne": null}
// }
// NATIJA: Har qanday user bilan login!
javascript// ❌ MongoDB Operator injection
app.get('/users', (req, res) => {
    const role = req.query.role;
    
    db.collection('users').find({
        role: role
    }).toArray((err, users) => {
        res.json(users);
    });
});

// HUJUM:
// GET /users?role[$regex]=.*
// Barcha userlar qaytariladi
✅ Xavfsiz Kod
javascript// ✅ NODE.JS - Input validation va sanitization
const validator = require('validator');

app.post('/login', async (req, res) => {
    let { username, password } = req.body;
    
    // 1. Type checking
    if (typeof username !== 'string' || typeof password !== 'string') {
        return res.status(400).json({ error: 'Invalid input type' });
    }
    
    // 2. Input validation
    if (!validator.isAlphanumeric(username) || username.length > 50) {
        return res.status(400).json({ error: 'Invalid username' });
    }
    
    // 3. Sanitize (object'larni string'ga)
    username = String(username);
    password = String(password);
    
    // 4. Xavfsiz query
    const user = await db.collection('users').findOne({
        username: username,
        password: password  // Production'da hash qilingan bo'lishi kerak!
    });
    
    if (user) {
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid credentials' });
    }
});

// ✅ Mongoose schema bilan (type safety)
const userSchema = new mongoose.Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' }
});

const User = mongoose.model('User', userSchema);

// Query
const user = await User.findOne({
    username: username,
    password: hashedPassword
});

3. OS Command Injection
❌ Xavfli Kod
python# ❌ PYTHON - Direct command execution
import os

filename = request.form['filename']
os.system(f"cat {filename}")

# HUJUM:
# filename: file.txt; rm -rf /
# NATIJA: cat file.txt; rm -rf /
# Barcha fayllar o'chiriladi!
javascript// ❌ NODE.JS - exec without sanitization
const { exec } = require('child_process');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    
    exec(`ping -c 4 ${ip}`, (error, stdout, stderr) => {
        res.send(stdout);
    });
});

// HUJUM:
// GET /ping?ip=8.8.8.8; cat /etc/passwd
// NATIJA: Parollar fayli o'qiladi
php// ❌ PHP - shell_exec
$file = $_GET['file'];
$output = shell_exec("ls -la " . $file);
echo $output;

// HUJUM:
// GET /?file=.; whoami
// NATIJA: Current user ko'rsatiladi
✅ Xavfsiz Kod
python# ✅ PYTHON - Input validation va safe functions
import subprocess
import re

def ping_host(ip):
    # 1. IP validation
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        raise ValueError("Invalid IP address")
    
    # 2. IP range check
    octets = ip.split('.')
    if any(int(octet) > 255 for octet in octets):
        raise ValueError("Invalid IP address")
    
    # 3. Safe command execution (list format)
    try:
        result = subprocess.run(
            ['ping', '-c', '4', ip],  # List, not string!
            capture_output=True,
            text=True,
            timeout=10,
            check=True
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Error: {e}"
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"

# Ishlatish
ip = request.form['ip']
try:
    output = ping_host(ip)
    return jsonify({'output': output})
except ValueError as e:
    return jsonify({'error': str(e)}), 400
javascript// ✅ NODE.JS - execFile with validation
const { execFile } = require('child_process');
const validator = require('validator');

app.get('/ping', (req, res) => {
    const ip = req.query.ip;
    
    // 1. Validation
    if (!validator.isIP(ip)) {
        return res.status(400).json({ error: 'Invalid IP address' });
    }
    
    // 2. Whitelist characters
    if (!/^[0-9.]+$/.test(ip)) {
        return res.status(400).json({ error: 'Invalid characters' });
    }
    
    // 3. execFile (safer than exec)
    execFile('ping', ['-c', '4', ip], {
        timeout: 10000,
        maxBuffer: 1024 * 1024
    }, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Command failed' });
        }
        res.json({ output: stdout });
    });
});
php// ✅ PHP - escapeshellarg
$file = $_GET['file'];

// 1. Validation
if (!preg_match('/^[a-zA-Z0-9_\-\.]+$/', $file)) {
    die("Invalid filename");
}

// 2. Whitelist directory
$base_dir = '/var/www/uploads/';
$full_path = realpath($base_dir . $file);

if (strpos($full_path, $base_dir) !== 0) {
    die("Directory traversal detected");
}

// 3. Use escapeshellarg
$safe_file = escapeshellarg($full_path);
$output = shell_exec("ls -la " . $safe_file);

echo htmlspecialchars($output);
Command Injection Aniqlash
python# ✅ Dangerous characters check
def is_command_injection(input_string):
    """Command injection pattern'larni aniqlash"""
    
    dangerous_chars = [
        ';', '|', '&', '$', '`', '\n', '\r',
        '$(', '${', '<!--', '-->', '<', '>',
        '||', '&&', '|&'
    ]
    
    for char in dangerous_chars:
        if char in input_string:
            return True
    
    # Command patterns
    command_patterns = [
        r'\b(cat|ls|whoami|id|pwd|wget|curl|nc|netcat|bash|sh|cmd|powershell)\b'
    ]
    
    for pattern in command_patterns:
        if re.search(pattern, input_string, re.IGNORECASE):
            return True
    
    return False

4. LDAP Injection
❌ Xavfli Kod
python# ❌ PYTHON - Direct LDAP query
import ldap

username = request.form['username']
password = request.form['password']

filter_str = f"(&(uid={username})(userPassword={password}))"
result = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)

# HUJUM:
# username: *)(uid=*))(|(uid=*
# NATIJA: (&(uid=*)(uid=*))(|(uid=*)(userPassword=anything))
# Barcha userlar qaytariladi
✅ Xavfsiz Kod
python# ✅ PYTHON - LDAP escaping
import ldap.filter

username = request.form['username']
password = request.form['password']

# Escape special characters
safe_username = ldap.filter.escape_filter_chars(username)
safe_password = ldap.filter.escape_filter_chars(password)

filter_str = f"(&(uid={safe_username})(userPassword={safe_password}))"
result = ldap_conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)

5. Server-Side Template Injection (SSTI)
❌ Xavfli Kod
python# ❌ FLASK/JINJA2 - Direct template rendering
from flask import Flask, request, render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name')
    template = f"<h1>Hello {name}!</h1>"
    return render_template_string(template)

# HUJUM:
# GET /hello?name={{7*7}}
# NATIJA: <h1>Hello 49!</h1>

# Xavfliroq:
# GET /hello?name={{config}}
# NATIJA: Flask config ko'rinadi (SECRET_KEY ham!)

# Eng xavfli:
# GET /hello?name={{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}
# NATIJA: Remote Code Execution!
javascript// ❌ NODE.JS - Pug/Jade unsafe
const pug = require('pug');

app.get('/profile', (req, res) => {
    const name = req.query.name;
    const template = `html
  body
    h1 Hello #{name}!`;
    
    const html = pug.render(template);
    res.send(html);
});

// HUJUM:
// GET /profile?name=#{process.env}
// NATIJA: Environment variables ko'rinadi
✅ Xavfsiz Kod
python# ✅ FLASK - Use templates, not string interpolation
from flask import Flask, request, render_template

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    
    # Template file ishlatish
    return render_template('hello.html', name=name)

# hello.html (autoescaping yoniq)
# <h1>Hello {{ name }}!</h1>

# Yoki manual escaping
from markupsafe import escape

@app.route('/hello')
def hello():
    name = request.args.get('name', 'Guest')
    return f"<h1>Hello {escape(name)}!</h1>"
javascript// ✅ NODE.JS - Use compiled templates
const pug = require('pug');
const path = require('path');

// Pre-compile template
const compiledFunction = pug.compileFile(
    path.join(__dirname, 'views', 'profile.pug')
);

app.get('/profile', (req, res) => {
    const name = req.query.name || 'Guest';
    
    // Render with data (auto-escaped)
    const html = compiledFunction({ name: name });
    res.send(html);
});

// profile.pug
// html
//   body
//     h1= name

6. XML Injection (XXE - XML External Entity)
❌ Xavfli Kod
python# ❌ PYTHON - Unsafe XML parsing
import xml.etree.ElementTree as ET

xml_data = request.data
root = ET.fromstring(xml_data)

# HUJUM:
# <?xml version="1.0"?>
# <!DOCTYPE foo [
#   <!ENTITY xxe SYSTEM "file:///etc/passwd">
# ]>
# <user>
#   <name>&xxe;</name>
# </user>
# NATIJA: /etc/passwd fayli o'qiladi
✅ Xavfsiz Kod
python# ✅ PYTHON - Defusedxml
from defusedxml import ElementTree as ET

xml_data = request.data

try:
    # External entities o'chirilgan
    root = ET.fromstring(xml_data)
except ET.ParseError as e:
    return "Invalid XML", 400

# Yoki manual defenses
import xml.etree.ElementTree as ET

parser = ET.XMLParser()
parser.entity = {}  # External entities block
parser.parser.SetParamEntityParsing(0)  # Param entities block

root = ET.fromstring(xml_data, parser=parser)

Universal Input Validation
python# ✅ Comprehensive input validator
import re
from typing import Any, List, Optional

class InputValidator:
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 255) -> str:
        """Remove dangerous characters"""
        if not isinstance(value, str):
            raise ValueError("Input must be string")
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Limit length
        value = value[:max_length]
        
        return value.strip()
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Email validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email)) and len(email) <= 254
    
    @staticmethod
    def validate_username(username: str) -> bool:
        """Username validation"""
        # Faqat alphanumeric va underscore
        pattern = r'^[a-zA-Z0-9_]{3,20}$'
        return bool(re.match(pattern, username))
    
    @staticmethod
    def validate_integer(value: Any, min_val: int = None, max_val: int = None) -> int:
        """Integer validation with range"""
        try:
            num = int(value)
            if min_val is not None and num < min_val:
                raise ValueError(f"Value must be >= {min_val}")
            if max_val is not None and num > max_val:
                raise ValueError(f"Value must be <= {max_val}")
            return num
        except (ValueError, TypeError):
            raise ValueError("Invalid integer")
    
    @staticmethod
    def validate_sql_safe(value: str) -> bool:
        """Check for SQL injection patterns"""
        dangerous_patterns = [
            r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC)\b)",
            r"(--|#|\/\*|\*\/)",
            r"(\';|\";)",
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, value, re.IGNORECASE):
                return False
        return True
    
    @staticmethod
    def validate_filename(filename: str) -> bool:
        """Safe filename validation"""
        # Faqat alphanumeric, dash, underscore va dot
        pattern = r'^[a-zA-Z0-9_\-\.]+$'
        if not re.match(pattern, filename):
            return False
        
        # Path traversal tekshirish
        if '..' in filename or '/' in filename or '\\' in filename:
            return False
        
        return True
    
    @staticmethod
    def validate_url(url: str, allowed_schemes: List[str] = ['http', 'https']) -> bool:
        """URL validation"""
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(url)
            return parsed.scheme in allowed_schemes and bool(parsed.netloc)
        except:
            return False

# Ishlatish
validator = InputValidator()

@app.route('/api/user', methods=['POST'])
def create_user():
    username = request.json.get('username')
    email = request.json.get('email')
    age = request.json.get('age')
    
    # Validation
    if not validator.validate_username(username):
        return {"error": "Invalid username"}, 400
    
    if not validator.validate_email(email):
        return {"error": "Invalid email"}, 400
    
    try:
        age = validator.validate_integer(age, min_val=1, max_val=150)
    except ValueError as e:
        return {"error": str(e)}, 400
    
    # Safe to use
    user = User.create(username=username, email=email, age=age)
    return {"id": user.id}, 201
Web Application Firewall (WAF) Rules
nginx# ✅ ModSecurity rules (Nginx)

# SQL Injection
SecRule ARGS "@detectSQLi" \
    "id:1001,phase:2,deny,status:403,msg:'SQL Injection Detected'"

# XSS
SecRule ARGS "@detectXSS" \
    "id:1002,phase:2,deny,status:403,msg:'XSS Attack Detected'"

# Command Injection
SecRule ARGS "@rx (;|\||&|\$\(|`)" \
    "id:1003,phase:2,deny,status:403,msg:'Command Injection Detected'"

# Path Traversal
SecRule ARGS "@rx (\.\.\/|\.\.\\)" \
    "id:1004,phase:2,deny,status:403,msg:'Path Traversal Detected'"
Security Testing
python# ✅ Automated injection testing
import requests

def test_sql_injection(url, param):
    """Test SQL injection vulnerabilities"""
    
    payloads = [
        "' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND 1=1--",
        "1' AND 1=2--",
    ]
    
    for payload in payloads:
        response = requests.get(url, params={param: payload})
        
        # Check for SQL errors
        error_indicators = [
            'mysql', 'sql', 'sqlite', 'postgresql',
            'syntax error', 'unexpected', 'warning'
        ]
        
        content = response.text.lower()
        for indicator in error_indicators:
            if indicator in content:
                print(f"[!] Potential SQLi found with payload: {payload}")
                return True
    
    return False

def test_command_injection(url, param):
    """Test command injection"""
    
    payloads = [
        "; ls",
        "| whoami",
        "& ping -c 1 127.0.0.1",
        "`id`",
        "$(cat /etc/passwd)"
    ]
    
    for payload in payloads:
        response = requests.get(url, params={param: payload})
        
        # Check for command output
        indicators = ['root:', 'uid=', 'gid=', 'bin/bash']
        
        content = response.text
        for indicator in indicators:
            if indicator in content:
                print(f"[!] Potential Command Injection: {payload}")
                return True
    
    return False

# Run tests
test_sql_injection('http://example.com/search', 'q')
test_command_injection('http://example.com/ping', 'ip')
Best Practices Summary
✅ QILING:

Prepared Statements - har doim parameterized queries
Input Validation - barcha input'larni tekshirish
Output Encoding - ma'lumotlarni encode qilish
Principle of Least Privilege - minimal database permissions
WAF ishlatish - Web Application Firewall
ORM ishlatish - raw SQL o'rniga
Whitelist approach - faqat ruxsat berilganlar
Error handling - generic error messages
Regular updates - libraries va frameworks
Security testing - automated scanning

❌ QILMANG:

String concatenation SQL'da
Direct command execution
User input'ni trust qilish
Dynamic query building
Blacklist approach (incomplete)
Detailed error messages production'da
Root yoki admin permissions
Client-side validation'ga ishonish
Old libraries ishlatish
Manual escaping (built-in functions o'rniga)