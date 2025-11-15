Software and Data Integrity Failures - Batafsil Ma'lumot
Nima bu?
Software and Data Integrity Failures - bu dastur yoki ma'lumotlarning to'g'riligini (integrity) tekshirmasdan ishonish natijasida yuzaga keladigan xavfsizlik zaifligidir. OWASP Top 10 (2021) ro'yxatida #8 o'rinda turadi.
Bu zaifliklar quyidagilarni o'z ichiga oladi:

Insecure deserialization - Xavfli ma'lumotlarni deserialize qilish
CI/CD pipeline compromise - Build jarayoniga hujum
Supply chain attacks - Dependency'lar orqali zaharlanish
Auto-update mechanisms - Yangilanishlarni tekshirmaslik
Unsigned code - Digital signature yo'q

Real-World Misollar
1. SolarWinds Supply Chain Attack (2020)
🔴 SOLARWINDS BREACH (2020)

Hujum turi: Supply Chain Attack
Ta'sir: 18,000+ organizatsiya (Microsoft, Intel, Cisco, etc.)
Qanday: Build server'ga kirish → Orion software'ga backdoor

Timeline:
- 2019 Sentabr: Build server compromise
- 2020 Mart: Trojanized update release
- 2020 Dekabr: Breach aniqlandi

Zarar: Billions of dollars
Sabab: 
  ❌ Weak build server security
  ❌ No code signing verification
  ❌ No integrity checks on updates
2. Codecov Supply Chain Attack (2021)
🔴 CODECOV BREACH (2021)

Hujum: Docker image manipulation
Ta'sir: 29,000 customers
Qanday: Bash Uploader script compromise

Sabab:
  ❌ No script integrity verification
  ❌ Credentials in environment variables
  ❌ No monitoring on build artifacts
Asosiy Zaiflik Turlari

1. Insecure Deserialization
Nima bu?
Serialization - object'ni byte stream'ga aylantirish (saqlash/yuborish uchun)
Deserialization - byte stream'ni qayta object'ga aylantirish
MUAMMO: Trust qilinmagan ma'lumotlarni deserialize qilish → RCE!
❌ Xavfli Kod (Java)
java// ❌ JAVA - Unsafe deserialization
import java.io.*;

public class UserService {
    public User loadUser(byte[] userData) {
        try {
            ObjectInputStream ois = new ObjectInputStream(
                new ByteArrayInputStream(userData)
            );
            
            // XAVFLI: Har qanday object deserialize qilinadi!
            User user = (User) ois.readObject();
            return user;
            
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

// HUJUM:
// Hujumchi ysoserial tool bilan payload yaratadi:
// java -jar ysoserial.jar CommonsCollections6 "rm -rf /" > payload.bin
// Bu payload deserialize qilinganda code execute bo'ladi!
python# ❌ PYTHON - Unsafe pickle
import pickle
import base64

def load_session(cookie):
    # Cookie'dan session data deserialize qilish
    session_data = base64.b64decode(cookie)
    session = pickle.loads(session_data)  # ❌ XAVFLI!
    return session

# HUJUM:
# import pickle, os, base64
# 
# class Exploit:
#     def __reduce__(self):
#         return (os.system, ('rm -rf /',))
# 
# payload = base64.b64encode(pickle.dumps(Exploit()))
# # Bu payload deserialize qilinganda command execute bo'ladi!
php// ❌ PHP - unserialize
<?php
$user_data = $_COOKIE['user'];
$user = unserialize($user_data);  // ❌ XAVFLI!

// HUJUM:
// class Exploit {
//     public $cmd;
//     function __destruct() {
//         system($this->cmd);
//     }
// }
// 
// $exploit = new Exploit();
// $exploit->cmd = "cat /etc/passwd";
// $payload = serialize($exploit);
// setcookie('user', $payload);
?>
✅ Xavfsiz Kod
java// ✅ JAVA - Safe alternatives

// Option 1: JSON ishlatish (Jackson)
import com.fasterxml.jackson.databind.ObjectMapper;

public class UserService {
    private final ObjectMapper mapper = new ObjectMapper();
    
    public User loadUser(String jsonData) {
        try {
            // JSON deserialize (safe)
            return mapper.readValue(jsonData, User.class);
        } catch (Exception e) {
            throw new RuntimeException("Invalid user data", e);
        }
    }
    
    public String saveUser(User user) {
        try {
            return mapper.writeValueAsString(user);
        } catch (Exception e) {
            throw new RuntimeException("Serialization failed", e);
        }
    }
}

// Option 2: Agar Java serialization kerak bo'lsa
import java.io.*;

public class SafeObjectInputStream extends ObjectInputStream {
    
    // Whitelist classes
    private static final Set<String> ALLOWED_CLASSES = Set.of(
        "com.myapp.User",
        "com.myapp.Session",
        "java.util.HashMap"
    );
    
    public SafeObjectInputStream(InputStream in) throws IOException {
        super(in);
    }
    
    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) 
            throws IOException, ClassNotFoundException {
        
        String className = desc.getName();
        
        // Faqat whitelist'dagi classlar
        if (!ALLOWED_CLASSES.contains(className)) {
            throw new InvalidClassException(
                "Unauthorized deserialization attempt", className);
        }
        
        return super.resolveClass(desc);
    }
}

// Ishlatish
public User loadUser(byte[] userData) {
    try (SafeObjectInputStream ois = new SafeObjectInputStream(
            new ByteArrayInputStream(userData))) {
        return (User) ois.readObject();
    } catch (Exception e) {
        throw new RuntimeException("Deserialization failed", e);
    }
}
python# ✅ PYTHON - Safe alternatives

# Option 1: JSON ishlatish
import json
from typing import Dict, Any

def save_session(session_data: Dict[str, Any]) -> str:
    """Safe session serialization"""
    return json.dumps(session_data)

def load_session(cookie: str) -> Dict[str, Any]:
    """Safe session deserialization"""
    try:
        session = json.loads(cookie)
        
        # Validate structure
        if not isinstance(session, dict):
            raise ValueError("Invalid session format")
        
        # Validate keys
        allowed_keys = {'user_id', 'username', 'role', 'expires'}
        if not set(session.keys()).issubset(allowed_keys):
            raise ValueError("Invalid session keys")
        
        return session
    except (json.JSONDecodeError, ValueError) as e:
        raise ValueError(f"Invalid session: {e}")

# Option 2: Signed tokens (JWT)
import jwt
from datetime import datetime, timedelta

SECRET_KEY = os.getenv('JWT_SECRET_KEY')

def create_session_token(user_id: int, username: str) -> str:
    """Create signed JWT token"""
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm='HS256')

def verify_session_token(token: str) -> Dict[str, Any]:
    """Verify and decode JWT"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")

# Option 3: Agar pickle kerak bo'lsa (hmac bilan)
import pickle
import hmac
import hashlib

SECRET = os.getenv('PICKLE_SECRET').encode()

def safe_pickle_dumps(obj):
    """Pickle with HMAC signature"""
    pickled = pickle.dumps(obj)
    signature = hmac.new(SECRET, pickled, hashlib.sha256).digest()
    return signature + pickled

def safe_pickle_loads(data):
    """Unpickle with HMAC verification"""
    signature = data[:32]
    pickled = data[32:]
    
    # Verify signature
    expected = hmac.new(SECRET, pickled, hashlib.sha256).digest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError("Invalid signature")
    
    return pickle.loads(pickled)
php// ✅ PHP - Safe alternatives

<?php
// Option 1: JSON
function save_session($data) {
    return json_encode($data);
}

function load_session($cookie) {
    $data = json_decode($cookie, true);
    
    // Validate
    if (!is_array($data)) {
        throw new Exception("Invalid session");
    }
    
    $allowed_keys = ['user_id', 'username', 'role'];
    $keys = array_keys($data);
    
    if (array_diff($keys, $allowed_keys)) {
        throw new Exception("Invalid session keys");
    }
    
    return $data;
}

// Option 2: Signed serialize
function safe_serialize($data, $secret) {
    $serialized = serialize($data);
    $signature = hash_hmac('sha256', $serialized, $secret);
    return $signature . $serialized;
}

function safe_unserialize($data, $secret) {
    $signature = substr($data, 0, 64);
    $serialized = substr($data, 64);
    
    // Verify signature
    $expected = hash_hmac('sha256', $serialized, $secret);
    if (!hash_equals($signature, $expected)) {
        throw new Exception("Invalid signature");
    }
    
    // Whitelist classes
    $options = [
        'allowed_classes' => ['User', 'Session']
    ];
    
    return unserialize($serialized, $options);
}
?>

2. CI/CD Pipeline Security
❌ Xavfli CI/CD
yaml# ❌ .github/workflows/deploy.yml - INSECURE
name: Deploy

on: [push]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2  # ❌ Old version
      
      - name: Install dependencies
        run: npm install  # ❌ No lock file check
      
      - name: Build
        run: |
          npm run build
          # ❌ No integrity check
      
      - name: Deploy
        env:
          AWS_ACCESS_KEY: ${{ secrets.AWS_KEY }}  # ❌ Plaintext in logs
        run: |
          aws s3 sync ./dist s3://mybucket --delete
          # ❌ No verification
✅ Xavfsiz CI/CD
yaml# ✅ .github/workflows/deploy.yml - SECURE
name: Secure Deploy

on:
  push:
    branches:
      - main

permissions:
  contents: read
  id-token: write  # OIDC token

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4  # ✅ Latest version
        with:
          persist-credentials: false
      
      - name: Verify commit signature
        run: |
          git verify-commit HEAD || exit 1
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Verify lock file
        run: |
          if [ ! -f package-lock.json ]; then
            echo "No lock file found!"
            exit 1
          fi
      
      - name: Install dependencies
        run: npm ci  # ✅ Clean install from lock file
      
      - name: Audit dependencies
        run: npm audit --audit-level=high
      
      - name: SAST scan
        uses: github/codeql-action/analyze@v2
      
      - name: Dependency scan
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  
  build:
    needs: security-scan
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test
      
      - name: Build
        run: npm run build
      
      - name: Generate SBOM
        run: |
          npm install -g @cyclonedx/cyclonedx-npm
          cyclonedx-npm --output-file sbom.json
      
      - name: Sign artifacts
        run: |
          # Sign build artifacts
          cosign sign-blob --key cosign.key dist/bundle.js > bundle.sig
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: build-artifacts
          path: |
            dist/
            sbom.json
            bundle.sig
          retention-days: 30
  
  deploy:
    needs: build
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Download artifacts
        uses: actions/download-artifact@v3
        with:
          name: build-artifacts
      
      - name: Verify signature
        run: |
          cosign verify-blob --key cosign.pub --signature bundle.sig dist/bundle.js
      
      - name: Configure AWS credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789:role/GithubActionsRole
          aws-region: us-east-1
      
      - name: Deploy to S3
        run: |
          aws s3 sync ./dist s3://mybucket \
            --delete \
            --metadata "commit=${{ github.sha }},build=${{ github.run_id }}"
      
      - name: Invalidate CloudFront
        run: |
          aws cloudfront create-invalidation \
            --distribution-id E1234567890 \
            --paths "/*"
      
      - name: Verify deployment
        run: |
          # Health check
          curl -f https://myapp.com/health || exit 1
      
      - name: Notify success
        if: success()
        run: |
          curl -X POST ${{ secrets.SLACK_WEBHOOK }} \
            -H 'Content-Type: application/json' \
            -d '{"text":"✅ Deployment successful: ${{ github.sha }}"}'
      
      - name: Rollback on failure
        if: failure()
        run: |
          # Automatic rollback
          aws s3 sync s3://mybucket-backup s3://mybucket --delete
✅ GitLab CI/CD Security
yaml# ✅ .gitlab-ci.yml - SECURE
variables:
  SECURE_LOG_LEVEL: "info"
  FF_USE_FASTZIP: "true"

stages:
  - security
  - build
  - test
  - deploy

# Security scanning
sast:
  stage: security
  image: registry.gitlab.com/gitlab-org/security-products/sast:latest
  script:
    - /analyzer run
  artifacts:
    reports:
      sast: gl-sast-report.json

dependency_scanning:
  stage: security
  image: registry.gitlab.com/gitlab-org/security-products/dependency-scanning:latest
  script:
    - /analyzer run
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json

secret_detection:
  stage: security
  image: registry.gitlab.com/gitlab-org/security-products/secret-detection:latest
  script:
    - /analyzer run
  artifacts:
    reports:
      secret_detection: gl-secret-detection-report.json

# Build with integrity
build:
  stage: build
  image: node:20-alpine
  before_script:
    - apk add --no-cache cosign
  script:
    # Verify dependencies
    - npm ci --audit
    
    # Build
    - npm run build
    
    # Generate SBOM
    - npx @cyclonedx/cyclonedx-npm --output-file sbom.json
    
    # Sign artifacts
    - cosign sign-blob --key $COSIGN_KEY dist/app.js > app.sig
  artifacts:
    paths:
      - dist/
      - sbom.json
      - app.sig
    expire_in: 1 week

# Deploy with verification
deploy:
  stage: deploy
  image: alpine:latest
  before_script:
    - apk add --no-cache aws-cli cosign
  script:
    # Verify signature
    - cosign verify-blob --key $COSIGN_PUBLIC_KEY --signature app.sig dist/app.js
    
    # Deploy
    - aws s3 sync dist/ s3://$S3_BUCKET/
  environment:
    name: production
    url: https://myapp.com
  only:
    - main
  when: manual

3. Software Supply Chain Security
✅ Package Integrity Verification
javascript// ✅ Subresource Integrity (SRI) for CDN
<!DOCTYPE html>
<html>
<head>
    <!-- ✅ With SRI hash -->
    <script 
        src="https://cdn.jsdelivr.net/npm/jquery@3.6.0/dist/jquery.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
        crossorigin="anonymous">
    </script>
    
    <!-- ❌ Without SRI - XAVFLI! -->
    <!-- <script src="https://cdn.example.com/library.js"></script> -->
</head>
</html>

// Generate SRI hash
const crypto = require('crypto');
const fs = require('fs');

function generateSRI(filename) {
    const fileBuffer = fs.readFileSync(filename);
    const hashSum = crypto.createHash('sha384');
    hashSum.update(fileBuffer);
    const hash = hashSum.digest('base64');
    
    return `sha384-${hash}`;
}

console.log(generateSRI('jquery.min.js'));
✅ NPM Package Verification
bash# ✅ Install with integrity check
npm install --package-lock-only

# ✅ Verify package integrity
npm audit signatures

# ✅ Check package reputation
npx socket-security analyze package.json

# ✅ Verify publisher
npm view express --json | jq '.maintainers'
javascript// ✅ .npmrc - Security settings
package-lock=true
audit=true
audit-level=moderate
fund=false

# Registry security
registry=https://registry.npmjs.org/
always-auth=true

# Verify signatures
verify-signatures=true
✅ Docker Image Integrity
dockerfile# ✅ Dockerfile with digest
FROM node:20-alpine@sha256:2d5e8a8a51bc341fd5f2eed6d91455c3a3d147e91a14298fc564b5dc519c1666

# ✅ Verify base image
RUN apk add --no-cache cosign && \
    cosign verify node:20-alpine

# ✅ Multi-stage build
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:20-alpine
WORKDIR /app
COPY --from=builder /app/node_modules ./node_modules
COPY . .

# ✅ Run as non-root
USER node

# ✅ Health check
HEALTHCHECK --interval=30s --timeout=3s \
    CMD node healthcheck.js

CMD ["node", "index.js"]
bash# ✅ Sign Docker image
docker build -t myapp:latest .

# Sign with Cosign
cosign sign --key cosign.key myapp:latest

# Verify signature
cosign verify --key cosign.pub myapp:latest

# Generate SBOM for image
syft myapp:latest -o json > sbom.json

# Scan for vulnerabilities
trivy image myapp:latest
grype myapp:latest

4. Code Signing
✅ Git Commit Signing
bash# ✅ Setup GPG
gpg --full-generate-key

# ✅ Configure Git
git config --global user.signingkey YOUR_KEY_ID
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# ✅ Sign commits
git commit -S -m "Secure commit"

# ✅ Verify commits
git log --show-signature

# ✅ Verify specific commit
git verify-commit HEAD
yaml# ✅ GitHub branch protection
# Require signed commits
branches:
  main:
    protection:
      required_signatures: true
      required_status_checks:
        strict: true
        contexts:
          - "security-scan"
          - "build"
      required_pull_request_reviews:
        required_approving_review_count: 2
✅ Code Signing Certificate
bash# ✅ Sign executable (Windows)
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com myapp.exe

# ✅ Verify signature
signtool verify /pa myapp.exe

# ✅ Sign JAR (Java)
jarsigner -keystore keystore.jks -signedjar signed.jar unsigned.jar alias

# ✅ Verify JAR
jarsigner -verify -verbose signed.jar

5. Secure Update Mechanisms
❌ Xavfli Update
javascript// ❌ Insecure auto-update
const http = require('http');
const fs = require('fs');

function checkForUpdates() {
    // ❌ HTTP (no encryption)
    http.get('http://updates.example.com/latest.json', (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
            const update = JSON.parse(data);
            
            // ❌ No signature verification
            downloadUpdate(update.url);
        });
    });
}

function downloadUpdate(url) {
    // ❌ Direct execution without verification
    http.get(url, (res) => {
        const file = fs.createWriteStream('update.exe');
        res.pipe(file);
        file.on('finish', () => {
            // ❌ Execute immediately
            require('child_process').exec('update.exe');
        });
    });
}
✅ Xavfsiz Update
javascript// ✅ Secure auto-update (Electron example)
const { autoUpdater } = require('electron-updater');
const crypto = require('crypto');
const https = require('https');

class SecureUpdater {
    constructor() {
        // ✅ HTTPS only
        autoUpdater.setFeedURL({
            provider: 'github',
            owner: 'mycompany',
            repo: 'myapp',
            private: true
        });
        
        // ✅ Signature verification
        autoUpdater.autoDownload = false;
        autoUpdater.autoInstallOnAppQuit = false;
    }
    
    async checkForUpdates() {
        try {
            const result = await autoUpdater.checkForUpdates();
            
            if (result.updateInfo) {
                // ✅ Verify signature
                const isValid = await this.verifySignature(
                    result.updateInfo.path,
                    result.updateInfo.signature
                );
                
                if (!isValid) {
                    throw new Error('Invalid update signature');
                }
                
                // ✅ User confirmation
                const userConsent = await this.askUserPermission(
                    result.updateInfo.version
                );
                
                if (userConsent) {
                    await autoUpdater.downloadUpdate();
                    autoUpdater.quitAndInstall();
                }
            }
        } catch (error) {
            console.error('Update failed:', error);
            this.reportError(error);
        }
    }
    
    async verifySignature(filePath, signature) {
        const publicKey = fs.readFileSync('public.pem', 'utf8');
        const fileBuffer = fs.readFileSync(filePath);
        
        const verify = crypto.createVerify('SHA256');
        verify.update(fileBuffer);
        
        return verify.verify(publicKey, signature, 'base64');
    }
    
    async askUserPermission(version) {
        const { dialog } = require('electron');
        const result = await dialog.showMessageBox({
            type: 'question',
            buttons: ['Install', 'Later'],
            title: 'Update Available',
            message: `Version ${version} is available. Install now?`
        });
        
        return result.response === 0;
    }
    
    reportError(error) {
        // ✅ Log error for monitoring
        https.post('https://api.myapp.com/errors', {
            error: error.message,
            version: app.getVersion(),
            timestamp: new Date().toISOString()
        });
    }
}

// Usage
const updater = new SecureUpdater();
setInterval(() => updater.checkForUpdates(), 24 * 60 * 60 * 1000);

6. Data Integrity Protection
✅ Database Integrity
python# ✅ Database integrity with checksums
import hashlib
import json
from datetime import datetime

class IntegrityProtectedModel:
    def __init__(self, db):
        self.db = db
    
    def calculate_checksum(self, data: dict) -> str:
        """Calculate SHA-256 checksum"""
        # Sort keys for consistent hashing
        sorted_data = json.dumps(data, sort_keys=True)
        return hashlib.sha256(sorted_data.encode()).hexdigest()
    
    def save(self, table: str, data: dict):
        """Save with integrity check"""
        # Add metadata
        data['created_at'] = datetime.utcnow().isoformat()
        data['checksum'] = self.calculate_checksum(data)
        
        # Save to database
        self.db.insert(table, data)
    
    def load(self, table: str, id: int) -> dict:
        """Load and verify integrity"""
        data = self.db.select(table, id)
        
        if not data:
            raise ValueError("Record not found")
        
        # Extract and remove checksum
        stored_checksum = data.pop('checksum')
        
        # Recalculate checksum
        calculated_checksum = self.calculate_checksum(data)
        
        # Verify
        if stored_checksum != calculated_checksum:
            raise ValueError("Data integrity violation detected!")
        
        return data
    
    def update(self, table: str, id: int, updates: dict):
        """Update with integrity check"""
        # Load existing data
        data = self.load(table, id)
        
        # Apply updates
        data.update(updates)
        data['modified_at'] = datetime.utcnow().isoformat()
        
        # Recalculate checksum
        data['checksum'] = self.calculate_checksum(data)
        
        # Save
        self.db.update(table, id, data)

# Usage
model = IntegrityProtectedModel(database)

# Save
model.save('users', {
    'username': 'john',
    'email': 'john@example.com'
})

# Load (automatically verifies)
user = model.load('users', 1)
✅ File Integrity Monitoring
python# ✅ File integrity monitoring
import os
import hashlib
import json
from pathlib import Path
from typing import Dict

class FileIntegrityMonitor:
    def __init__(self, watch_paths: list):
        self.watch_paths = watch_paths
        self.baseline_file = 'integrity_baseline.json'
    
    def calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 hash of file"""
        sha256 = hashlib.sha256()
        
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        
        return sha256.hexdigest()
    
    def create_baseline(self) -> Dict[str, str]:
        """Create integrity baseline"""
        baseline = {}
        
        for watch_path in self.watch_paths:
            for root, dirs, files in os.walk(watch_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    file_hash = self.calculate_file_hash(filepath)
                    
                    baseline[filepath] = {
                        'hash': file_hash,
                        'size': os.path.getsize(filepath),
                        'modified': os.path.getmtime(filepath)
                    }
        
        # Save baseline
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=2)
        
        return baseline
    
    def verify_integrity(self) -> Dict[str, list]:
        """Verify files against baseline"""
        # Load baseline
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        results = {
            'modified': [],
            'deleted': [],
            'new': []
        }
        
        # Check existing files
        current_files = set()
        for watch_path in self.watch_paths:
            for root, dirs, files in os.walk(watch_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    current_files.add(filepath)
                    
                    if filepath not in baseline:
                        results['new'].append(filepath)
                        continue
                    
                    # Calculate current hash
                    current_hash = self.calculate_file_hash(filepath)
                    
                    # Compare
                    if current_hash != baseline[filepath]['hash']:
                        results['modified'].append({
                            'file': filepath,
                            'expected': baseline[filepath]['hash'],
                            'actual': current_hash
                        })
        
        # Check for deleted files
        for filepath in baseline:
            if filepath not in current_files:
                results['deleted'].append(filepath)
        
        return resultsRetryBContinuepython    def alert_on_changes(self, results: Dict[str, list]):
        """Alert on integrity violations"""
        if any(results.values()):
            alert_message = "🚨 FILE INTEGRITY VIOLATION DETECTED!\n\n"
            
            if results['modified']:
                alert_message += "Modified files:\n"
                for item in results['modified']:
                    alert_message += f"  - {item['file']}\n"
                    alert_message += f"    Expected: {item['expected']}\n"
                    alert_message += f"    Actual:   {item['actual']}\n"
            
            if results['deleted']:
                alert_message += "\nDeleted files:\n"
                for file in results['deleted']:
                    alert_message += f"  - {file}\n"
            
            if results['new']:
                alert_message += "\nNew files:\n"
                for file in results['new']:
                    alert_message += f"  - {file}\n"
            
            # Send alert
            self.send_alert(alert_message)
    
    def send_alert(self, message: str):
        """Send alert to monitoring system"""
        import requests
        
        # Log to file
        with open('integrity_violations.log', 'a') as f:
            f.write(f"{datetime.now()}: {message}\n\n")
        
        # Send to Slack/email/SIEM
        webhook = os.getenv('ALERT_WEBHOOK')
        if webhook:
            requests.post(webhook, json={'text': message})

# Usage
monitor = FileIntegrityMonitor([
    '/var/www/html',
    '/etc/nginx',
    '/usr/local/bin'
])

# Create baseline
monitor.create_baseline()

# Regular verification (run in cron)
results = monitor.verify_integrity()
if any(results.values()):
    monitor.alert_on_changes(results)

7. API Response Integrity
✅ HMAC Signature
javascript// ✅ API with HMAC signatures
const crypto = require('crypto');
const express = require('express');

const app = express();
const SECRET_KEY = process.env.API_SECRET_KEY;

// Middleware to verify HMAC
function verifyHMAC(req, res, next) {
    const signature = req.headers['x-signature'];
    const timestamp = req.headers['x-timestamp'];
    
    if (!signature || !timestamp) {
        return res.status(401).json({ error: 'Missing signature' });
    }
    
    // Prevent replay attacks (5 minute window)
    const now = Date.now();
    if (Math.abs(now - parseInt(timestamp)) > 300000) {
        return res.status(401).json({ error: 'Request expired' });
    }
    
    // Calculate expected signature
    const payload = JSON.stringify(req.body) + timestamp;
    const expected = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(payload)
        .digest('hex');
    
    // Compare signatures (timing-safe)
    if (!crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
    )) {
        return res.status(401).json({ error: 'Invalid signature' });
    }
    
    next();
}

// Sign response
function signResponse(data) {
    const timestamp = Date.now().toString();
    const payload = JSON.stringify(data) + timestamp;
    
    const signature = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(payload)
        .digest('hex');
    
    return {
        data: data,
        timestamp: timestamp,
        signature: signature
    };
}

// Protected endpoint
app.post('/api/transaction', verifyHMAC, (req, res) => {
    const { amount, recipient } = req.body;
    
    // Process transaction
    const result = processTransaction(amount, recipient);
    
    // Sign response
    const signed = signResponse(result);
    
    res.json(signed);
});

// Client-side verification
async function callAPI(endpoint, data) {
    const timestamp = Date.now().toString();
    const payload = JSON.stringify(data) + timestamp;
    
    const signature = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(payload)
        .digest('hex');
    
    const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-Signature': signature,
            'X-Timestamp': timestamp
        },
        body: JSON.stringify(data)
    });
    
    const result = await response.json();
    
    // Verify response signature
    const responsePayload = JSON.stringify(result.data) + result.timestamp;
    const expectedSig = crypto
        .createHmac('sha256', SECRET_KEY)
        .update(responsePayload)
        .digest('hex');
    
    if (result.signature !== expectedSig) {
        throw new Error('Response integrity check failed');
    }
    
    return result.data;
}

8. Blockchain for Audit Trail
✅ Immutable Audit Log
python# ✅ Blockchain-based audit trail
import hashlib
import json
from datetime import datetime
from typing import List, Dict, Any

class Block:
    def __init__(self, index: int, timestamp: str, data: Dict[str, Any], 
                 previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate block hash"""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'data': self.data,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int):
        """Proof of work"""
        target = '0' * difficulty
        
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()

class AuditBlockchain:
    def __init__(self, difficulty: int = 4):
        self.chain: List[Block] = []
        self.difficulty = difficulty
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """Create first block"""
        genesis = Block(
            0,
            datetime.utcnow().isoformat(),
            {'message': 'Genesis Block'},
            '0'
        )
        genesis.mine_block(self.difficulty)
        self.chain.append(genesis)
    
    def get_latest_block(self) -> Block:
        """Get last block in chain"""
        return self.chain[-1]
    
    def add_audit_record(self, record: Dict[str, Any]) -> Block:
        """Add new audit record"""
        # Add metadata
        record['recorded_by'] = record.get('user', 'system')
        record['ip_address'] = record.get('ip', 'unknown')
        
        # Create new block
        new_block = Block(
            len(self.chain),
            datetime.utcnow().isoformat(),
            record,
            self.get_latest_block().hash
        )
        
        # Mine block (proof of work)
        new_block.mine_block(self.difficulty)
        
        # Add to chain
        self.chain.append(new_block)
        
        return new_block
    
    def verify_chain(self) -> bool:
        """Verify blockchain integrity"""
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]
            
            # Verify current block hash
            if current_block.hash != current_block.calculate_hash():
                print(f"Block {i} has been tampered with!")
                return False
            
            # Verify chain linkage
            if current_block.previous_hash != previous_block.hash:
                print(f"Block {i} chain broken!")
                return False
            
            # Verify proof of work
            target = '0' * self.difficulty
            if current_block.hash[:self.difficulty] != target:
                print(f"Block {i} proof of work invalid!")
                return False
        
        return True
    
    def get_audit_trail(self, user_id: str = None) -> List[Dict[str, Any]]:
        """Get audit trail (optionally filtered by user)"""
        trail = []
        
        for block in self.chain[1:]:  # Skip genesis
            if user_id is None or block.data.get('user_id') == user_id:
                trail.append({
                    'index': block.index,
                    'timestamp': block.timestamp,
                    'action': block.data.get('action'),
                    'user': block.data.get('user'),
                    'details': block.data.get('details'),
                    'hash': block.hash
                })
        
        return trail
    
    def export_chain(self, filename: str):
        """Export blockchain to file"""
        chain_data = []
        
        for block in self.chain:
            chain_data.append({
                'index': block.index,
                'timestamp': block.timestamp,
                'data': block.data,
                'previous_hash': block.previous_hash,
                'hash': block.hash,
                'nonce': block.nonce
            })
        
        with open(filename, 'w') as f:
            json.dump(chain_data, f, indent=2)

# Usage
audit_chain = AuditBlockchain(difficulty=4)

# Log audit events
audit_chain.add_audit_record({
    'action': 'user_login',
    'user_id': 'user123',
    'user': 'john@example.com',
    'ip': '192.168.1.100',
    'details': {'method': '2FA'}
})

audit_chain.add_audit_record({
    'action': 'data_access',
    'user_id': 'user123',
    'user': 'john@example.com',
    'ip': '192.168.1.100',
    'details': {
        'resource': 'customer_database',
        'records': 150
    }
})

audit_chain.add_audit_record({
    'action': 'privilege_escalation',
    'user_id': 'admin456',
    'user': 'admin@example.com',
    'ip': '192.168.1.200',
    'details': {
        'target_user': 'user123',
        'new_role': 'admin'
    }
})

# Verify integrity
if audit_chain.verify_chain():
    print("✅ Audit trail integrity verified")
else:
    print("❌ Audit trail has been tampered with!")

# Get audit trail
trail = audit_chain.get_audit_trail(user_id='user123')
for record in trail:
    print(f"{record['timestamp']}: {record['action']} by {record['user']}")

# Export for compliance
audit_chain.export_chain('audit_trail.json')

9. Secure Build Pipeline
✅ Reproducible Builds
dockerfile# ✅ Reproducible Docker build
FROM node:20-alpine@sha256:exact-digest

# Set build timestamp for reproducibility
ARG BUILD_DATE
ENV BUILD_DATE=${BUILD_DATE}

# Install dependencies with exact versions
WORKDIR /app
COPY package-lock.json ./
RUN npm ci --only=production \
    && npm cache clean --force

# Copy source
COPY . .

# Build with deterministic output
RUN npm run build

# Metadata
LABEL org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.opencontainers.image.version="${VERSION}"

USER node
CMD ["node", "index.js"]
bash# ✅ Build script with verification
#!/bin/bash
set -euo pipefail

# Variables
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse HEAD)
VERSION=$(cat package.json | jq -r .version)

# Build Docker image
docker build \
    --build-arg BUILD_DATE="$BUILD_DATE" \
    --build-arg GIT_COMMIT="$GIT_COMMIT" \
    --build-arg VERSION="$VERSION" \
    -t myapp:$VERSION \
    .

# Generate SBOM
syft myapp:$VERSION -o cyclonedx-json > sbom-$VERSION.json

# Scan for vulnerabilities
trivy image --severity HIGH,CRITICAL myapp:$VERSION

# Sign image
cosign sign --key cosign.key myapp:$VERSION

# Generate attestation
cosign attest --key cosign.key \
    --predicate sbom-$VERSION.json \
    myapp:$VERSION

# Push to registry
docker tag myapp:$VERSION registry.example.com/myapp:$VERSION
docker push registry.example.com/myapp:$VERSION

# Verify after push
cosign verify --key cosign.pub registry.example.com/myapp:$VERSION

echo "✅ Build completed and verified"

10. Runtime Integrity Monitoring
✅ Application Self-Verification
python# ✅ Runtime integrity check
import os
import hashlib
import sys
from typing import Dict

class RuntimeIntegrityMonitor:
    def __init__(self, expected_hashes_file: str):
        self.expected_hashes = self.load_expected_hashes(expected_hashes_file)
    
    def load_expected_hashes(self, filename: str) -> Dict[str, str]:
        """Load expected file hashes"""
        import json
        with open(filename, 'r') as f:
            return json.load(f)
    
    def calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA-256 of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def verify_application_integrity(self) -> bool:
        """Verify application files haven't been modified"""
        violations = []
        
        for filepath, expected_hash in self.expected_hashes.items():
            if not os.path.exists(filepath):
                violations.append(f"Missing: {filepath}")
                continue
            
            actual_hash = self.calculate_file_hash(filepath)
            
            if actual_hash != expected_hash:
                violations.append(f"Modified: {filepath}")
        
        if violations:
            self.handle_integrity_violation(violations)
            return False
        
        return True
    
    def handle_integrity_violation(self, violations: list):
        """Handle detected integrity violations"""
        alert = "🚨 CRITICAL: Application integrity violation!\n\n"
        alert += "\n".join(violations)
        
        # Log
        with open('security.log', 'a') as f:
            f.write(f"{datetime.now()}: {alert}\n")
        
        # Alert
        self.send_alert(alert)
        
        # Shutdown application
        print(alert, file=sys.stderr)
        sys.exit(1)
    
    def send_alert(self, message: str):
        """Send security alert"""
        import requests
        webhook = os.getenv('SECURITY_WEBHOOK')
        if webhook:
            requests.post(webhook, json={'text': message, 'level': 'critical'})

# Usage in application startup
def main():
    # Verify integrity before starting
    monitor = RuntimeIntegrityMonitor('integrity_manifest.json')
    
    if not monitor.verify_application_integrity():
        print("Application integrity check failed!")
        sys.exit(1)
    
    print("✅ Application integrity verified")
    
    # Start application
    start_application()

if __name__ == '__main__':
    main()

Best Practices Summary
✅ QILING:

Never trust deserialization - JSON ishlatish yoki whitelist
Sign everything - commits, artifacts, images, updates
Verify signatures - har doim verify qilish
Use HTTPS everywhere - SSL/TLS majburiy
Implement SRI - CDN resources uchun
SBOM generation - har bir build uchun
Integrity monitoring - FIM (File Integrity Monitoring)
Secure CI/CD - pipeline hardening
Code signing - digital certificates
Audit blockchain - immutable logs
HMAC signatures - API integrity
Reproducible builds - deterministic output
Runtime verification - self-checking
Dependency pinning - exact versions
Regular scanning - automated tools

❌ QILMANG:

Unsigned code execute qilish
HTTP orqali updates
Signature verification skip qilish
Insecure deserialization
Weak CI/CD pipeline
No integrity checks
Trust external sources blindly
No audit trail
Manual verification
Ignoring security alerts

🔍 TEKSHIRISH:
bash# Daily checks
npm audit
snyk test
trivy image app:latest

# Pre-deployment
cosign verify image
git verify-commit HEAD
npm ci --audit

# Runtime
./integrity-check.sh
./verify-deployment.sh

# Post-deployment
./smoke-test.sh
curl -f https://api.example.com/health
```

### 📊 MONITORING:
```
Monitor:
- Build pipeline security
- Dependency vulnerabilities
- Code signing status
- Integrity violations
- Unauthorized changes
- Failed verifications
- Supply chain attacks
- Update failures
```

### 🎯 KEY METRICS:
```
Track:
- Time to patch vulnerabilities
- Number of unsigned artifacts
- Integrity check failures
- Supply chain risk score
- Build reproducibility rate
- Signature verification rate
- Audit trail completeness