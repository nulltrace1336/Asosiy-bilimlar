Broken Access Control - Batafsil Ma'lumot
Nima bu?
Broken Access Control - bu foydalanuvchilar o'z ruxsatlaridan tashqaridagi resurslarga kirish imkoniyatiga ega bo'lgan xavfsizlik zaifligidir. OWASP Top 10 (2021) ro'yxatida #1 o'rinda turadi.
Asosiy Turlari
1. Vertical Access Control (Vertikal Nazorat Buzilishi)
Oddiy foydalanuvchi admin funksiyalariga kiradi:

/admin panelga kirish
Privilegiyalangan API so'rovlarini bajarish
Tizim sozlamalarini o'zgartirish

2. Horizontal Access Control (Gorizontal Nazorat Buzilishi)
Bir xil darajadagi foydalanuvchilar bir-birining ma'lumotlariga kiradi:

Boshqa foydalanuvchilarning profilini ko'rish/tahrirlash
URL'dagi ID ni o'zgartirish: /user/123 → /user/124

3. Context-Dependent Access Control
Jarayonlarni buzib o'tish:

To'lovni amalga oshirmasdan mahsulotni olish
Workflow bosqichlarini o'tkazib yuborish

Keng Tarqalgan Zaifliklar
❌ Xavfli misollar:

1. URL orqali to'g'ridan-to'g'ri kirish:
   /api/users/456/delete (auth tekshiruvsiz)

2. ID parametrini o'zgartirish:
   /invoice?id=123 → /invoice?id=124

3. POST so'rovda role o'zgartirish:
   {"user_id": 123, "role": "admin"}

4. Hidden form field manipulation:
   <input type="hidden" name="role" value="user">

5. Cookie/Token manipulation:
   isAdmin=false → isAdmin=true
Aniqlash Usullari
1. Manual Testing (Qo'lda Tekshirish)
bash# Turli foydalanuvchilar bilan test
# User A sifatida:
GET /api/profile/user_a

# User B sifatida xuddi shu so'rov:
GET /api/profile/user_a  # Muvaffaqiyatli bo'lmasligi kerak!

# ID Enumeration:
GET /api/invoice/1
GET /api/invoice/2
GET /api/invoice/3
...
```

### 2. **Burp Suite bilan**
- **Intruder** - ID'larni avtomatik almashtirish
- **Repeater** - So'rovlarni qayta jo'natish
- **Autorize** extension - avtomatik access control tekshiruvi

### 3. **OWASP ZAP**
```
Active Scan → Access Control Testing
4. Postman/Insomnia
javascript// Turli tokenlar bilan bir xil endpoint'ga so'rov
GET /api/sensitive-data
Headers: 
  Authorization: Bearer <user_token>
  Authorization: Bearer <admin_token>
Himoya Choralari
1. Server-Side Tekshiruv ✅
python# Python/Flask misoli
from flask import session, abort

@app.route('/api/user/<int:user_id>')
def get_user(user_id):
    # Har doim server tomonida tekshiring!
    if session['user_id'] != user_id and not session['is_admin']:
        abort(403)  # Forbidden
    
    user = User.query.get(user_id)
    return jsonify(user.to_dict())
javascript// Node.js/Express misoli
app.get('/api/invoice/:id', async (req, res) => {
    const invoice = await Invoice.findById(req.params.id);
    
    // Foydalanuvchi faqat o'z invoice'lariga kirishi mumkin
    if (invoice.userId !== req.user.id) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    res.json(invoice);
});
2. Role-Based Access Control (RBAC)
javascript// Middleware misoli
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'Insufficient permissions' });
        }
        next();
    };
};

// Foydalanish
app.delete('/api/user/:id', 
    authenticate, 
    checkRole(['admin']), 
    deleteUser
);
3. Attribute-Based Access Control (ABAC)
pythondef can_access_document(user, document):
    # Murakkab shartlar
    if user.id == document.owner_id:
        return True
    if document.is_public:
        return True
    if user.department == document.department and document.shared:
        return True
    return False
4. Xavfsiz ID Generatsiya
javascript// UUID ishlatish (taxmin qilib bo'lmaydigan)
const { v4: uuidv4 } = require('uuid');

const newUser = {
    id: uuidv4(), // a3bb189e-8bf9-3888-9912-ace4e6543002
    name: "John"
};

// Ketma-ket raqamlar o'rniga ❌
// id: 1, 2, 3, 4...
5. Default Deny Approach
javascript// Hamma narsa taqiqlangan, faqat ruxsat berilganlar mumkin
const permissions = {
    'admin': ['read', 'write', 'delete'],
    'user': ['read'],
    'guest': []
};

function hasPermission(role, action) {
    return permissions[role]?.includes(action) || false;
}
```

## Best Practices (Eng Yaxshi Amaliyotlar)

### ✅ QILING:
1. **Har bir so'rovda** server tomonida autentifikatsiya va avtorizatsiyani tekshiring
2. **Deny by default** - faqat aniq ruxsat berilgan resurslar ochiq
3. **Logging** - barcha kirish urinishlarini yozib boring
4. **Testing** - har bir yangi feature uchun access control testlari
5. **Minimal Privilege** - foydalanuvchilarga faqat kerakli ruxsatlar

### ❌ QILMANG:
1. Client-side tekshiruvga tayanmang
2. URL yoki ID'larni taxmin qilish oson qilmang
3. Hidden field'larga ishonmang
4. Sessiyalarni to'g'ri tekshirmasdan API'larga ruxsat bermang

## Test Qilish Ro'yxati
```
☐ Har bir endpoint uchun autentifikatsiya majburiy
☐ Horizontal privilege escalation test qilindi
☐ Vertical privilege escalation test qilindi
☐ Direct object reference zaifliklar yo'q
☐ Rate limiting qo'shilgan
☐ Logging va monitoring ishlamoqda
☐ Session management xavfsiz
☐ API endpoint'lar himoyalangan
☐ File upload/download nazorat ostida
☐ Admin panel ajratilgan va himoyalangan
```

## Real-World Misollar

**IDOR (Insecure Direct Object Reference):**
```
https://bank.com/api/account/12345/transactions
                                 ↑
                    Buni o'zgartirish orqali boshqa hisoblarni ko'rish
```

**Function Level:**
```
POST /api/deleteUser
{"userId": "victim_id"}

Normal user bu API'ni chaqirmasligi kerak!