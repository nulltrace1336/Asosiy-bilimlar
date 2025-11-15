1️⃣ Bash Scripting Nima?

Bash — Bourne Again SHell ning qisqartmasi.
Bash skriptlar — bu bir nechta komandalarni ketma-ket ishlatadigan fayl.
Skripting yordamida siz:

fayllarni boshqarish

tizim monitoringi

avtomatlashtirilgan vazifalarni bajarish

foydalanuvchi interaktivligini yaratish

… va boshqa ko‘plab narsalarni qilishingiz mumkin.

2️⃣ Bash Skript Yaratish
2.1 Skript faylini yaratish
```bash
nano myscript.sh
```

Yoki boshqa text editor bilan.

2.2 Shebang (skript boshlanishi)

Skriptning birinchi qatori:
```bash
#!/bin/bash
```

Bu tizimga “bu fayl bash orqali ishlatiladi” degan ma’lumot beradi.

2.3 Oddiy misol
```bash
#!/bin/bash
echo "Salom, Dunyo!"
```

Faylni saqlang va chiqish:
```bash
chmod +x myscript.sh   # skriptni bajariladigan qilamiz
./myscript.sh          # skriptni ishga tushiramiz
```
3️⃣ O‘zgaruvchilar
```bash
#!/bin/bash
ism="Behruz"
echo "Salom, $ism!"
```

O‘zgaruvchi nomi: ```A-Z, a-z, 0-9, _``` bilan bo‘lishi mumkin, raqam bilan boshlanmaydi.

$ belgisini ishlatish orqali qiymatga murojaat qilamiz.

4️⃣ Foydalanuvchidan kirish
```bash
#!/bin/bash
read -p "Ismingizni kiriting: " ism
echo "Salom, $ism!"
```
5️⃣ Shartlar (if)
```bash
#!/bin/bash
read -p "Yoshingizni kiriting: " yosh

if [ $yosh -ge 18 ]; then
    echo "Siz kattasiz."
else
    echo "Siz hali kichkinsiz."
fi
```

-ge → greater or equal (>=)

-lt → less than (<)

6️⃣ Looplar
6.1 For loop
```bash
#!/bin/bash
for i in {1..5}; do
    echo "Soni: $i"
done
```

6.2 While loop
```bash
#!/bin/bash
count=1
while [ $count -le 5 ]; do
    echo "Soni: $count"
    ((count++))
done
```
7️⃣ Funksiyalar
```bash
#!/bin/bash
salom_ber() {
    echo "Salom, $1!"
}

salom_ber "Behruz"
salom_ber "Ali"
```

$1 → birinchi argument

$2 → ikkinchi argument va hokazo

8️⃣ Fayllar bilan ishlash
```bash
#!/bin/bash
filename="test.txt"

# Fayl mavjudligini tekshirish
if [ -f "$filename" ]; then
    echo "$filename mavjud"
else
    echo "$filename mavjud emas"
fi
```

9️⃣ Ba’zi foydali komandalar

```ls``` — katalogni ko‘rsatish

```pwd``` — joriy katalog

```mkdir``` — katalog yaratish

```rm``` — fayl yoki katalog o‘chirish

```grep``` — matn qidirish

```awk``` — matnni tahlil qilish

```sed``` — matnni almashtirish