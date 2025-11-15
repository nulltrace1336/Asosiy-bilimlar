Python Kirish

Python — yuqori darajali, interpretatsiya qilinadigan, keng qo‘llaniladigan dasturlash tili.
Asosiy xususiyatlari:

Oddiy sintaksis

Keng kutubxonalar ekotizimi

Ko‘p maqsadli (web, data science, automation, AI)

OOP va funksional dasturlashni qo‘llab-quvvatlaydi

Python fayllari .py kengaytmada bo‘ladi va interpreter yordamida ishlaydi:
```bash
python filename.py
```
2. O‘zgaruvchilar va Ma’lumot Turlari
O‘zgaruvchilar
```bash
x = 10       # integer
y = 3.14     # float
name = "Behruz"  # string
is_active = True  # boolean
```
Ma’lumot turlari
Type	Misol	Tavsif
int	10	Butun son
float	3.14	O‘nlik son
str	"Salom"	Matn
bool	True / False	Mantiqiy qiymat
list	[1,2,3]	Ro‘yxat
tuple	(1,2,3)	O‘zgarmas ro‘yxat
set	{1,2,3}	Takrorlanmas elementlar
dict	{"a":1, "b":2}	Lug‘at (kalit:qiymat)
3. Operatorlar
Arifmetik
```bash
a = 10
b = 3
print(a + b)  # 13
print(a - b)  # 7
print(a * b)  # 30
print(a / b)  # 3.333...
print(a // b) # 3 (butun bo‘lish)
print(a % b)  # 1 (qoldiq)
print(a ** b) # 1000 (daraja)
```
Taqqoslash
```bash
print(a > b)  # True
print(a < b)  # False
print(a == b) # False
print(a != b) # True
```
Mantiqiy
```bash
print(a > 5 and b < 5)  # True
print(a < 5 or b < 5)   # True
print(not(a > b))        # False
```
4. Shartlar (if, elif, else)
```bash
age = 18
if age >= 18:
    print("Siz kattasiz")
elif age > 12:
    print("Siz o‘smirdirsiz")
else:
    print("Siz bola ekansiz")
```
5. Sikllar
```bash
for sikli
for i in range(5):
    print(i)  # 0,1,2,3,4

while sikli
x = 0
while x < 5:
    print(x)
    x += 1
```
6. Funksiyalar
```bash
def greet(name):
    return f"Salom, {name}!"

print(greet("Behruz"))

Default va Keyword argumentlar
def greet(name="Dunyo"):
    return f"Salom, {name}!"

print(greet())        # Salom, Dunyo!
print(greet("Ali"))   # Salom, Ali!
```
7. Ma’lumot Tuzilmalari Batafsil
List
```bash
fruits = ["olma", "banan", "anor"]
fruits.append("apelsin")
fruits.remove("banan")
print(fruits[0])  # olma
```
Tuple (o‘zgarmas)
```bash
coordinates = (10, 20)
print(coordinates[0])  # 10
```
Set (unik elementlar)
```bash
nums = {1,2,3,3}
nums.add(4)
nums.remove(2)
print(nums)  # {1,3,4}
```
Dictionary (kalit:qiymat)
```bash
person = {"name": "Behruz", "age": 20}
print(person["name"])  # Behruz
person["age"] = 21
person["city"] = "Tashkent"
```
8. Fayllar bilan ishlash
```bash
# Faylga yozish
with open("test.txt", "w") as f:
    f.write("Salom Behruz")

# Fayldan o‘qish
with open("test.txt", "r") as f:
    content = f.read()
    print(content)
```
9. OOP (Object-Oriented Programming)
```bash
class Person:
    def __init__(self, name, age):
        self.name = name
        self.age = age

    def greet(self):
        return f"Salom, men {self.name}man"

p1 = Person("Behruz", 20)
print(p1.greet())
```
10. Modul va Kutubxonalar
```bash
import math
print(math.sqrt(16))  # 4.0

from random import randint
print(randint(1, 10))
```

Keng qo‘llaniladigan kutubxonalar:

Data Science: numpy, pandas, matplotlib

Web: flask, django, requests

Automation: selenium, pyautogui

11. Exception Handling (Xatolarni ushlash)
```bash
try:
    x = 10 / 0
except ZeroDivisionError:
    print("Nolga bo‘lish mumkin emas")
finally:
    print("Ish tugadi")
```
12. List Comprehension (Tez va qulay list yaratish)
```bash
nums = [x**2 for x in range(5)]
print(nums)  # [0,1,4,9,16]
```
13. Lambda va Funksiyalarni Yuqori Darajali
```bash
square = lambda x: x**2
print(square(5))  # 25

nums = [1,2,3,4,5]
evens = list(filter(lambda x: x%2==0, nums))
print(evens)  # [2,4]
```