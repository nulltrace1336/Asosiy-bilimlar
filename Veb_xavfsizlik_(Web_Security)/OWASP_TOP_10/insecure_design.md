Insecure Design - Batafsil Ma'lumot
Nima bu?
Insecure Design - bu dastur arxitekturasi va dizayn bosqichida qilingan xatoliklar. OWASP Top 10 (2021) ro'yxatida #4 o'rinda turadi.
Bu implementatsiya xatosi EMAS, balki dizayn darajasidagi zaiflik. Ya'ni, kod to'g'ri yozilgan bo'lishi mumkin, lekin tizimning o'zi xavfsiz loyihalashtirilmagan.
Insecure Design vs Insecure Implementation
🎨 INSECURE DESIGN (Dizayn xatosi):
- Threat modeling qilinmagan
- Security requirements yo'q
- Business logic zaif
- Xavfsizlik boshidan o'ylanmagan

🐛 INSECURE IMPLEMENTATION (Implementatsiya xatosi):
- SQL Injection
- XSS
- Buffer Overflow
- To'g'ri dizayn, lekin noto'g'ri kod
Asosiy Muammolar
1. Business Logic Zaifliklar
Tizim mantiq xatolariga yo'l qo'yadi
2. Threat Modeling Yo'qligi
Xavflar oldindan tahlil qilinmagan
3. Security by Obscurity
"Hech kim bilmaydi" deb o'ylash
4. Insufficient Security Requirements
Xavfsizlik talablari aniq emas
Real-World Misollar
❌ Misol 1: Parol Tiklash (Password Recovery)
python# XAVFLI DIZAYN
@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    
    # Faqat email orqali yangi parol yuborish
    user = User.query.filter_by(email=email).first()
    if user:
        new_password = generate_random_password()
        user.password = hash_password(new_password)
        send_email(email, f"Your new password: {new_password}")
    
    return "If email exists, password sent"

# MUAMMO:
# 1. Email hijack qilinsa?
# 2. Man-in-the-middle email o'qisa?
# 3. Secret question yo'q
# 4. Two-factor yo'q
✅ XAVFSIZ DIZAYN:
python@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    user = User.query.filter_by(email=email).first()
    
    if user:
        # 1. Time-limited token yaratish
        token = secrets.token_urlsafe(32)
        expiry = datetime.now() + timedelta(hours=1)
        
        PasswordReset.create(
            user_id=user.id,
            token=hash_token(token),
            expires_at=expiry
        )
        
        # 2. Token orqali link yuborish
        reset_link = f"https://example.com/reset/{token}"
        send_email(email, f"Reset link: {reset_link}")
    
    # 3. Har doim bir xil javob (user enumeration oldini olish)
    return "If email exists, reset link sent"

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    reset_req = PasswordReset.query.filter_by(
        token=hash_token(token),
        used=False
    ).first()
    
    # Token tekshiruvi
    if not reset_req or reset_req.is_expired():
        abort(400, "Invalid or expired token")
    
    if request.method == 'POST':
        new_password = request.form['password']
        
        # 4. Password strength tekshirish
        if not is_strong_password(new_password):
            return "Password too weak", 400
        
        user = User.query.get(reset_req.user_id)
        user.password = hash_password(new_password)
        reset_req.used = True
        
        # 5. Xabardor qilish
        send_email(user.email, "Your password was changed")
        
        return redirect('/login')
❌ Misol 2: E-Commerce - Price Manipulation
javascript// XAVFLI DIZAYN
app.post('/checkout', (req, res) => {
    const { items, totalPrice } = req.body;
    
    // Client'dan kelgan narxga ishonish!
    const order = {
        items: items,
        total: totalPrice,  // ❌ Client belgilaydi!
        userId: req.user.id
    };
    
    Order.create(order);
    processPayment(totalPrice);
});

// HUJUM:
// POST /checkout
// {
//   "items": [{"id": 1, "name": "Laptop", "price": 1}],
//   "totalPrice": 1  // $1000 o'rniga $1!
// }
✅ XAVFSIZ DIZAYN:
javascriptapp.post('/checkout', async (req, res) => {
    const { items } = req.body;  // Faqat item ID'lar
    
    // 1. Server tomonida narxlarni hisoblash
    let calculatedTotal = 0;
    const validatedItems = [];
    
    for (const item of items) {
        // 2. Har bir itemni database'dan tekshirish
        const product = await Product.findById(item.id);
        
        if (!product || !product.in_stock) {
            return res.status(400).json({ 
                error: 'Invalid product' 
            });
        }
        
        // 3. Server tomonida narxni olish
        calculatedTotal += product.price * item.quantity;
        
        validatedItems.push({
            productId: product.id,
            name: product.name,
            price: product.price,  // Database'dan
            quantity: item.quantity
        });
    }
    
    // 4. Inventory tekshirish
    for (const item of validatedItems) {
        if (!await checkInventory(item.productId, item.quantity)) {
            return res.status(400).json({ 
                error: 'Insufficient stock' 
            });
        }
    }
    
    // 5. Transaksiya ichida order yaratish
    const order = await db.transaction(async (trx) => {
        const newOrder = await Order.create({
            userId: req.user.id,
            items: validatedItems,
            total: calculatedTotal,  // Server hisoblagani
            status: 'pending'
        }, { transaction: trx });
        
        // 6. Inventory'ni kamaytirish
        for (const item of validatedItems) {
            await Product.decrement('stock', {
                by: item.quantity,
                where: { id: item.productId }
            }, { transaction: trx });
        }
        
        return newOrder;
    });
    
    // 7. To'lovni qayta ishlash
    try {
        await processPayment(order.id, calculatedTotal);
        await order.update({ status: 'paid' });
    } catch (error) {
        // Rollback qilish
        await order.update({ status: 'failed' });
        throw error;
    }
    
    res.json({ orderId: order.id, total: calculatedTotal });
});
❌ Misol 3: Rate Limiting Yo'q
python# XAVFLI DIZAYN
@app.route('/api/transfer', methods=['POST'])
def transfer_money():
    from_account = request.json['from']
    to_account = request.json['to']
    amount = request.json['amount']
    
    # Hech qanday limit yo'q!
    execute_transfer(from_account, to_account, amount)
    return {"status": "success"}

# HUJUM:
# 1000 marta/soniyada so'rov yuborish
# Brute force
# DoS hujum
✅ XAVFSIZ DIZAYN:
pythonfrom flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/transfer', methods=['POST'])
@limiter.limit("5 per minute")  # Har daqiqada 5 ta
@require_auth
def transfer_money():
    from_account = request.json['from']
    to_account = request.json['to']
    amount = request.json['amount']
    
    # 1. Daily limit tekshirish
    daily_total = get_user_daily_transfers(request.user.id)
    if daily_total + amount > DAILY_LIMIT:
        return {"error": "Daily limit exceeded"}, 429
    
    # 2. Balance tekshirish
    balance = get_balance(from_account)
    if balance < amount:
        return {"error": "Insufficient funds"}, 400
    
    # 3. Suspicious activity detection
    if is_suspicious_transfer(request.user.id, amount, to_account):
        # 2FA talab qilish
        if not verify_2fa(request.json.get('otp')):
            return {"error": "2FA required"}, 403
    
    # 4. Transaction log
    log_transaction(request.user.id, 'transfer', {
        'from': from_account,
        'to': to_account,
        'amount': amount,
        'ip': request.remote_addr
    })
    
    # 5. Transaksiya
    try:
        execute_transfer(from_account, to_account, amount)
        
        # 6. Notification
        notify_user(request.user.id, f"Transfer of ${amount} completed")
        
        return {"status": "success"}
    except Exception as e:
        log_error(e)
        return {"error": "Transfer failed"}, 500
❌ Misol 4: Cinema Ticket Booking - Race Condition
python# XAVFLI DIZAYN
@app.route('/book-seat', methods=['POST'])
def book_seat():
    seat_id = request.json['seat_id']
    
    # 1. O'rindiq bo'shmi tekshirish
    seat = Seat.query.get(seat_id)
    if not seat.is_available:
        return {"error": "Seat taken"}, 400
    
    # ⏱️ RACE CONDITION BU YERDA!
    # Bir vaqtning o'zida 2 ta user book qilishi mumkin
    
    # 2. O'rindiqni band qilish
    seat.is_available = False
    seat.user_id = request.user.id
    db.session.commit()
    
    return {"status": "booked"}
✅ XAVFSIZ DIZAYN:
pythonfrom sqlalchemy import select
from sqlalchemy.orm import Session

@app.route('/book-seat', methods=['POST'])
def book_seat():
    seat_id = request.json['seat_id']
    
    # Database transaction bilan
    try:
        with db.session.begin():
            # SELECT FOR UPDATE - row lock
            seat = db.session.query(Seat).filter_by(
                id=seat_id
            ).with_for_update().first()
            
            if not seat:
                return {"error": "Seat not found"}, 404
            
            if not seat.is_available:
                return {"error": "Seat already taken"}, 400
            
            # Atomik operatsiya
            seat.is_available = False
            seat.user_id = request.user.id
            seat.booked_at = datetime.now()
            
            # Booking yaratish
            booking = Booking(
                user_id=request.user.id,
                seat_id=seat_id,
                movie_id=seat.movie_id,
                status='confirmed'
            )
            db.session.add(booking)
        
        return {"status": "booked", "booking_id": booking.id}
        
    except Exception as e:
        db.session.rollback()
        return {"error": "Booking failed"}, 500
Yoki Redis bilan distributed lock:
pythonimport redis
import time

redis_client = redis.Redis()

@app.route('/book-seat', methods=['POST'])
def book_seat():
    seat_id = request.json['seat_id']
    lock_key = f"seat_lock:{seat_id}"
    
    # Distributed lock
    lock = redis_client.set(
        lock_key, 
        "locked", 
        nx=True,  # Faqat mavjud bo'lmasa set qil
        ex=10     # 10 soniya timeout
    )
    
    if not lock:
        return {"error": "Seat is being booked"}, 409
    
    try:
        seat = Seat.query.get(seat_id)
        
        if not seat.is_available:
            return {"error": "Seat taken"}, 400
        
        # Book qilish
        seat.is_available = False
        seat.user_id = request.user.id
        db.session.commit()
        
        return {"status": "booked"}
        
    finally:
        # Lock'ni ochish
        redis_client.delete(lock_key)
```

## Secure Design Principles

### 1. **Defense in Depth (Layered Security)**
```
┌─────────────────────────────────┐
│  WAF (Web Application Firewall) │
├─────────────────────────────────┤
│  Rate Limiting                  │
├─────────────────────────────────┤
│  Authentication & Authorization │
├─────────────────────────────────┤
│  Input Validation               │
├─────────────────────────────────┤
│  Business Logic Checks          │
├─────────────────────────────────┤
│  Database Constraints           │
├─────────────────────────────────┤
│  Encryption                     │
├─────────────────────────────────┤
│  Logging & Monitoring           │
└─────────────────────────────────┘
2. Principle of Least Privilege
python# ❌ XAVFLI
DATABASE_USER = "root"  # To'liq huquq

# ✅ XAVFSIZ
# Har bir service uchun alohida user
READ_ONLY_USER = "app_reader"      # Faqat SELECT
WRITE_USER = "app_writer"          # SELECT, INSERT, UPDATE
ADMIN_USER = "app_admin"           # Faqat migration uchun
3. Fail Securely
python# ❌ XAVFLI - Error'da access berish
try:
    check_permission(user, resource)
    return resource
except Exception:
    return resource  # ❌ Xatolikda ham beradi!

# ✅ XAVFSIZ - Error'da rad etish
try:
    check_permission(user, resource)
    return resource
except Exception as e:
    log_error(e)
    abort(403)  # ✅ Xatolikda ruxsat yo'q
4. Don't Trust Input
python# ❌ XAVFLI
age = int(request.form['age'])
if age > 0:
    save_user(age)

# Hujum: age = -5 yoki age = 999999

# ✅ XAVFSIZ
age = request.form.get('age')

# Validate
if not age or not age.isdigit():
    return "Invalid age", 400

age = int(age)

# Business rules
if age < 0 or age > 150:
    return "Age must be between 0 and 150", 400

save_user(age)
5. Secure by Default
python# ❌ XAVFLI
class User:
    def __init__(self, username):
        self.username = username
        self.is_admin = True  # ❌ Default admin!

# ✅ XAVFSIZ
class User:
    def __init__(self, username):
        self.username = username
        self.is_admin = False  # ✅ Default oddiy user
        self.email_verified = False
        self.account_locked = False
        self.failed_login_attempts = 0
```

## Threat Modeling - STRIDE
```
S - Spoofing (Identifikatsiya buzish)
T - Tampering (Ma'lumotlarni o'zgartirish)
R - Repudiation (Rad etish)
I - Information Disclosure (Ma'lumot oshkor qilish)
D - Denial of Service (Xizmatni buzish)
E - Elevation of Privilege (Huquqlarni oshirish)
```

### STRIDE Qo'llash Misoli:
```
🎯 FEATURE: User Registration

S - Spoofing:
  ❓ Kimdir boshqa odam nomidan ro'yxatdan o'tishi mumkinmi?
  ✅ Email verification talab qilish
  ✅ Phone number verification

T - Tampering:
  ❓ Registration jarayonida ma'lumot o'zgartirilishi mumkinmi?
  ✅ HTTPS ishlatish
  ✅ CSRF token
  ✅ Input validation

R - Repudiation:
  ❓ User "Men ro'yxatdan o'tmaganman" deb da'vo qilishi mumkinmi?
  ✅ Audit log
  ✅ Email confirmation
  ✅ IP address logging

I - Information Disclosure:
  ❓ Registration'da sensitive ma'lumot oshkor bo'lishi mumkinmi?
  ✅ "Username already exists" o'rniga umumiy xato
  ✅ Rate limiting (user enumeration oldini olish)

D - Denial of Service:
  ❓ Registration spam qilish mumkinmi?
  ✅ Rate limiting
  ✅ CAPTCHA
  ✅ Email verification

E - Elevation of Privilege:
  ❓ Oddiy user admin bo'lib ro'yxatdan o'tishi mumkinmi?
  ✅ Default role: 'user'
  ✅ Admin faqat backend'dan qo'shiladi
  ✅ Hidden field'larga ishonmaslik
Security Requirements Ro'yxati
Functional Security Requirements
markdown## Authentication
- [ ] Strong password policy (min 12 chars, complexity)
- [ ] Multi-factor authentication (2FA)
- [ ] Account lockout after 5 failed attempts
- [ ] Password reset via secure token (1-hour expiry)
- [ ] Session timeout (15 min inactivity)

## Authorization
- [ ] Role-based access control (RBAC)
- [ ] Least privilege principle
- [ ] Resource-level permissions
- [ ] Audit trail for all permission changes

## Data Protection
- [ ] Encryption at rest (AES-256)
- [ ] Encryption in transit (TLS 1.3)
- [ ] Sensitive data masking in logs
- [ ] Secure data deletion (overwrite)

## Input Validation
- [ ] Server-side validation for all inputs
- [ ] Whitelist approach
- [ ] File upload restrictions
- [ ] SQL injection prevention

## API Security
- [ ] Rate limiting (100 req/min per user)
- [ ] API key authentication
- [ ] Request signing
- [ ] API versioning

## Monitoring
- [ ] Failed login attempts
- [ ] Privilege escalation attempts
- [ ] Data access patterns
- [ ] Suspicious transactions
Security Design Patterns
1. Circuit Breaker Pattern
pythonfrom datetime import datetime, timedelta

class CircuitBreaker:
    def __init__(self, failure_threshold=5, timeout=60):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.failures = 0
        self.last_failure = None
        self.state = 'CLOSED'  # CLOSED, OPEN, HALF_OPEN
    
    def call(self, func, *args, **kwargs):
        if self.state == 'OPEN':
            if datetime.now() - self.last_failure > timedelta(seconds=self.timeout):
                self.state = 'HALF_OPEN'
            else:
                raise Exception("Circuit breaker is OPEN")
        
        try:
            result = func(*args, **kwargs)
            self.on_success()
            return result
        except Exception as e:
            self.on_failure()
            raise e
    
    def on_success(self):
        self.failures = 0
        self.state = 'CLOSED'
    
    def on_failure(self):
        self.failures += 1
        self.last_failure = datetime.now()
        if self.failures >= self.failure_threshold:
            self.state = 'OPEN'

# Ishlatish
payment_breaker = CircuitBreaker()

@app.route('/payment', methods=['POST'])
def process_payment():
    try:
        result = payment_breaker.call(
            third_party_payment_api,
            amount=request.json['amount']
        )
        return {"status": "success"}
    except Exception as e:
        return {"error": "Payment service unavailable"}, 503
2. Idempotency Pattern
pythonimport hashlib

@app.route('/api/create-order', methods=['POST'])
def create_order():
    # Idempotency key (client yuboradi)
    idempotency_key = request.headers.get('Idempotency-Key')
    
    if not idempotency_key:
        return {"error": "Idempotency-Key required"}, 400
    
    # Avval bajarilganmi tekshirish
    existing = IdempotentRequest.query.filter_by(
        key=idempotency_key,
        user_id=request.user.id
    ).first()
    
    if existing:
        # Bir xil so'rov - avvalgi natijani qaytarish
        return existing.response, existing.status_code
    
    # Yangi so'rov
    try:
        order = create_new_order(request.json)
        response = {"order_id": order.id, "status": "created"}
        
        # Natijani saqlash
        IdempotentRequest.create(
            key=idempotency_key,
            user_id=request.user.id,
            response=response,
            status_code=201
        )
        
        return response, 201
        
    except Exception as e:
        return {"error": str(e)}, 500
3. Bulkhead Pattern
pythonfrom concurrent.futures import ThreadPoolExecutor
import threading

# Har xil service uchun alohida thread pool
payment_pool = ThreadPoolExecutor(max_workers=5)
notification_pool = ThreadPoolExecutor(max_workers=10)
analytics_pool = ThreadPoolExecutor(max_workers=3)

@app.route('/checkout', methods=['POST'])
def checkout():
    order = create_order(request.json)
    
    # Parallel bajarish, lekin isolated
    payment_future = payment_pool.submit(process_payment, order)
    notification_future = notification_pool.submit(send_notification, order)
    analytics_future = analytics_pool.submit(log_analytics, order)
    
    # Payment kutish (critical)
    try:
        payment_result = payment_future.result(timeout=30)
    except Exception as e:
        return {"error": "Payment failed"}, 500
    
    # Boshqalari fail bo'lsa ham davom etadi
    return {"order_id": order.id, "status": "success"}
Best Practices
✅ QILING:

Threat modeling har bir feature uchun
Security requirements aniq yozing
Principle of least privilege
Defense in depth strategiyasi
Fail securely - xatolikda rad eting
Input validation server-side
Rate limiting va throttling
Audit logging barcha muhim actionlar
Security testing CI/CD'da
Regular security review

❌ QILMANG:

Security'ni oxirga qoldirish
Client-side validation'ga ishonish
"Hech kim bilmaydi" deb o'ylash
Business logic'ni client'ga ishonish
Error'larda sensitive info ko'rsatish
Single point of failure
Unlimited resource usage
Weak default configurations
Assuming trust
Ignoring edge cases

Security Testing
python# Unit test misoli
def test_price_manipulation():
    """Client narxni o'zgartira olmasligi kerak"""
    client = TestClient()
    
    # Hujum urinishi
    response = client.post('/checkout', json={
        'items': [{'id': 1, 'price': 0.01}],  # Fake narx
        'total': 0.01
    })
    
    # Server o'z narxini ishlatishi kerak
    assert response.status_code == 200
    order = Order.get(response.json['order_id'])
    assert order.total == ACTUAL_PRODUCT_PRICE  # Real narx

def test_rate_limiting():
    """Rate limit ishlashi kerak"""
    client = TestClient()
    
    # 100 ta so'rov yuborish
    for i in range(100):
        response = client.post('/api/transfer', json={...})
        if i < 5:
            assert response.status_code == 200
        else:
            assert response.status_code == 429  # Too Many Requests
