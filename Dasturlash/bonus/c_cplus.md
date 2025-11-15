🔥 C/C++ Binary Exploitation — To‘liq Qo‘llanma
📌 1. Kirish: Binary Exploitation nima?

Binary exploitation — bu C/C++ dasturlarning xotira boshqaruvi xatolaridan foydalanib, nazoratni qo‘lga olish texnikasi.

Eng ko‘p uchraydigan zaifliklar:

Stack-based buffer overflow

Heap-based overflow

Use-after-free

Double free

Format string vulnerability

Integer overflow

Return-Oriented Programming (ROP)

Bularning barchasi C/C++ ning past darajadagi xotira boshqaruvi tufayli paydo bo‘ladi.

🧱 2. Stack Memory Asosi

C funksiyalar chaqirilganda quyidagilar stekda joylashadi:

Qism	Vazifasi
Local variables	Funksiya ichidagi o‘zgaruvchilar
Saved EBP	Oldingi stack frame
Return Address	Funksiya tugaganda qaytadigan joy

Tasavvur qiling:

[ buffer ]
[ saved EBP ]
[ return address ]  ← bunda exploit qilinadi!


Demak, buffer overflow orqali return address ustiga yozib, boshqaruvni o‘g‘irlaymiz.

🔥 3. Stack Buffer Overflow (oddiy)

Zaif C kod:

#include <stdio.h>
#include <string.h>

void vulnerable() {
    char buf[32];
    gets(buf); // zaif funksiya!
    printf("You entered: %s\n", buf);
}

int main() {
    vulnerable();
    return 0;
}


Muammo:

gets() chegaralarni tekshirmaydi.

32 baytdan uzun kirish → return address ustiga yozadi.

🧨 4. Shellcode bilan ekspluatatsiya qilish

Oddiy payload tartibi:

[ padding ] + [ yangi EIP/RIP ] + [ shellcode ]


Masalan, AAAA…BBBB kabi.

🛑 Eslatma: Zamonaviy OSlarda himoya mexanizmlari bor:

ASLR (Address Randomization)

NX-bit (stack executable emas)

Stack canary (stack smashing protector)

PIE (Position-independent executable)

Exploit yaratishda bularni o‘chirib ishlaysiz:

gcc vuln.c -o vuln -fno-stack-protector -z execstack -no-pie

🔥 5. ROP Chains (Return-Oriented Programming)

Agar stack executable bo‘lmasa — shellcode ishlamaydi.

Shunda biz:

libc yoki binary ichidagi kichik instruktsiyalar (gadgets)

; ret bilan tugagan ketma-ketliklar

yordamida sistema funksiyalarini ishga tushiramiz.

Masalan, ROP orqali:

system("/bin/sh")


chaqiriladi.

🧩 6. Format String Vulnerability

Zaif kod:

printf(user_input);


Muammo: printf("%s", user_input) bo‘lishi kerak edi.

Hujumlar:

%x orqali stack o‘qish

%n orqali xotiraga yozish → return addressni o‘zgartirish

🍺 7. Heap Exploitation (glibc malloc)

Mashhur zaifliklar:

Heap overflow

Use-after-free

Double free

Unsorted bin attack

Tcache poisoning

Zaif misol:

char *a = malloc(16);
char *b = malloc(16);
free(a);
free(b);
free(a);  // double free


Tcache ichida xotira strukturalarini o‘zgartirib → malloc() orqali 任意 adresga yozishga erishiladi.

🔬 8. Praktik Muammolar (CTF usulida)
1) Stack overflow with shellcode

— Return addressga skok qilib shellcode ishga tushirasiz.

2) ROP challenge

— system("/bin/sh") chaqirish

3) Format string

— %n orqali GOT yozish → code execution

4) Heap challenge

— Tcache poisoning → __free_hook → system("/bin/sh")

⚙️ 9. Exploit yozish uchun vositalar
Vazifa	Asbob
Debug	gdb, pwndbg, gef, radare2
Fuzzer	AFL++, libFuzzer
Disassembler	Ghidra, IDA Free
Exploit framework	pwntools (Python)
Shellcode	msfvenom

pwntools minimal exploit:

from pwn import *

p = process("./vuln")
payload = b"A" * 40 + p64(0x40123a)
p.sendline(payload)
p.interactive()

📘 10. O‘rganish Tartibi (bosqichma-bosqich)
1️⃣ Asoslar

Stack

Registers

Calling conventions

GDB debugging

2️⃣ Classic stack overflow

EIP overwrite

Shellcode injection

3️⃣ ASLR bypass

Leaks

ret2libc

4️⃣ ROP

Gadgetlar qidirish

ROP chain yaratish

5️⃣ Format string

Memory read/write

6️⃣ Heap exploitation

Allocator understanding (bins, chunks)

Tcache poisoning