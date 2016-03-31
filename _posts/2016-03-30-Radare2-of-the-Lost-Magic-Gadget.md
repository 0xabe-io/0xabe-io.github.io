---
layout: post
title:  "Radare2 of the Lost Magic Gadget"
date:   2016-03-30 08:00
categories: howto exploit
---

OK this is a bad pun to a rather nice movie. You may already have heard of the
magic gadget that exists to rule them all, more seriously, a gadget located in
the libc that executes a shell by itself. The problem is that depending on the
Linux distribution and the version of the libc, it might located at different
places and have different instructions. Therefore we can't just search for a
sequence of bytes. In this blog post, I propose a rather easy and lightweight
method to finding it with [Radare 2][radare2]. Happy hunting!

# Radare 2

I won't write yet another post about useful Radare2 commands. There
are already useful ones such as Techorganic's [Radare 2 in 0x1E
minutes][r2techorganic], which shows its use while reversing a binary. I'll
just show how I search for the magic gadget.

Radare 2 usually comes packaged in many Linux distributions. There are also
[pre-built][r2dl] binaries for Windows, OS X and mobile platforms. In their
[download page][r2dl], the developers encourage to always use the latest [git
version][r2git], because it is a rapidly evolving project and a lot of
contributions are added on a daily basis. As an example, the version of Radare2
found in the Kali repositories is almost a year old.

## Few commands

For the sake of completeness of that post, I'll just explain the commands that
will be used.

When I want to analyze a binary I tend to always launch Radare2 with the `-A`
option to automatically launch the analysis of all referenced code:
{% highlight shell-session %}
$ r2 -A binary_to_analyze
{% endhighlight %}

The `?` command is used to get help. It can be added to any commands to
get specific help on that command:
{% highlight shell-session %}
[0x00020830]> ?
Usage: [.][times][cmd][~grep][@[@iter]addr!size][|>pipe] ; ...
Append '?' to any char command to get detailed help
Prefix with number to repeat command N times (f.ex: 3x)
|%var =valueAlias for 'env' command
| *off[=[0x]value]     Pointer read/write data/values (see ?v, wx, wv)
| (macro arg0 arg1)    Manage scripting macros
| .[-|(m)|f|!sh|cmd]   Define macro or load r2, cparse or rlang file
| = [cmd]              Run this command via rap://
| /                    Search for bytes, regexps, patterns, ..
| ! [cmd]              Run given command as in system(3)
| # [algo] [len]       Calculate hash checksum of current block
| #!lang [..]          Hashbang to run an rlang script
| a                    Perform analysis of code
[snip]
{% endhighlight %}

To look for a string inside a binary the `/` command can be used:
{% highlight shell-session%}
[0x00020830]> /?
|Usage: /[amx/] [arg]Search stuff (see 'e??search' for options)
| / foo\x00           search for string 'foo\0'
[snip]
{% endhighlight %}

To search for cross-references to a specific address the command `axt` is used.
Some might think that it is barbaric and impossible to remember such a command
name. My idea is to see Radare2 as a tree of commands and each letter in a
command is used to select a branch. In the above command we have `a`, `x` and
`t`.  Let's have a look at the corresponding help information:
{% highlight shell-session %}
[0x00020830]> ?
[snip]
| a                    Perform analysis of code
[snip]
[0x00020830]> a?
[snip]
| ax[?ld-*]         manage refs/xrefs (see also afx?)
[snip]
[0x00020830]> ax?
[snip]
| axt [addr]      find data/code references to this address
[snip]
{% endhighlight %}

The `pd N` command is used to print (`p`) dissassembly (`d`) for `N`
instructions. There are some more subcommands but they won't be used here:
{% highlight shell-session %}
[0x00020830]> pd?
|Usage: p[dD][ajbrfils] [sz] [arch] [bits] # Print Disassembly
| NOTE: len  parameter can be negative
| NOTE:      Pressing ENTER on empty command will repeat last pd command and also seek to end of disassembled range.
| pd N       disassemble N instructions
| pd -N      disassemble N instructions backward
| pD N       disassemble N bytes
| pda        disassemble all possible opcodes (byte per byte)
| pdb        disassemble basic block
| pdc        pseudo disassembler output in C-link syntax
| pdj        disassemble to json
| pdr        recursive disassemble across the function graph
| pdf        disassemble function
| pdi        like 'pi', with offset and bytes
| pdl        show instruction sizes
| pds        disassemble only strings (see pdsf)
| pdt        disassemble the debugger traces (see atd)
{% endhighlight %}

If no address is given, it will print at the current address that is shown in
the prompt:
{% highlight shell-session %}
[0x00020830]> pd 1
            ;-- __libc_main:
/ (fcn) entry0 16
|           0x00020830      4883ec08       sub rsp, 8
{% endhighlight %}

To print at (`@`) a selected address, we can either provide it as an argument
or change the current address:
{% highlight shell-session %}
[0x00020830]> pd 1 @0xd6063
|           0x000d6063      488d3d80e008.  lea rdi, qword [rip + 0x8e080] ; 0x1640ea ; hit1_0 ; "/bin/sh" @ 0x1640ea
[0x00020830]> 0xd6063
[0x000d6063]> pd 1
|           0x000d6063      488d3d80e008.  lea rdi, qword [rip + 0x8e080] ; 0x1640ea ; hit1_0 ; "/bin/sh" @ 0x1640ea
{% endhighlight %}

The address selection applies to all function that can operate on an address, such as `axt`.

It is possible to filter the output of a command (sort of a grep) with a `~`:
{% highlight shell-session %}
[0x00020830]> pd?~pdf
| pdf        disassemble function
{% endhighlight %}

# Magic Gadget

Now that we know a few commands, let the hunt begin. Basically the magic gadget
is a all-in-one gadget that invoke the [`execve`][execve] [`syscall`][syscall]
with `/bin/sh` as its first argument. The man pages shows that:

* `execve` takes three arguments
  * `filename`: a pointer to `/bin/sh` for the magic gadget
  * `argv`: a pointer to an array of arguments
  * `envp`: a pointer to an array of environment variables
* `syscall` are invoked with the following registers used to pass arguments:
  * `rax`: the number corresponding to the syscall (59 or 0x3b for `execve`)
  * `rdi`: the first argument (`filename`)
  * `rsi`: the second argument
  * `rdx`: the third argument

Basically the magic gadget has to do the following actions (not especially in that order):

* load the address of `/bin/sh` in the `rdi` register
* set the `rsi` and `rdx` registers
* either call `execve` or set the `rax` register and execute the `syscall` instruction

Let's start by looking for `/bin/sh`:
{% highlight shell-session %}
$ r2 -A libc-2.23.so
[0x00020830]> / /bin/sh
Searching 7 bytes from 0x00000270 to 0x003a0990: 2f 62 69 6e 2f 73 68 
Searching 7 bytes in [0x270-0x3a0990]
hits: 1
0x001640ea hit0_0 "/bin/sh"
{% endhighlight %}

Now that we know the address, we can look for references that loads it into `rdi`:
{% highlight shell-session %}
[0x00020830]> axt @0x001640ea ~lea rdi
data 0x3f4a1 lea rdi, qword [rip + 0x124c42] in sym.do_system
data 0xd6063 lea rdi, qword [rip + 0x8e080] in fcn.000d5f03
data 0xd9aa1 lea rdi, qword [rip + 0x8a642] in sym.script_execute
data 0xb8488 lea rdi, qword [rip + 0xabc5b] in sym.__execvpe
data 0xb83b7 lea rdi, qword [rip + 0xabd2c] in sym.__execvpe
data 0x67b06 lea rdi, qword [rip + 0xfc5dd] in sym._IO_new_proc_open
{% endhighlight %}

Let's have a look at those addresses:
{% highlight shell-session %}
[0x00020830]> pd 6 @0xd6063
|           0x000d6063      488d3d80e008.  lea rdi, qword [rip + 0x8e080] ; 0x1640ea ; hit0_0 ; "/bin/sh" @ 0x1640ea
|           0x000d606a      488b10         mov rdx, qword [rax]
|           0x000d606d      e8be19feff     call sym.__GI_execve
[snip]
{% endhighlight %}

We might be in the middle of the magic gadget because we already have `rdi` and
`rdx` registers set and the call to `execve`. Only `rsi` register is missing,
let's have a look at couple instructions above:
{% highlight shell-session %}
[0x00020830]> pd -2 @0xd6063
|           0x000d605c      2c00           sub al, 0
|           0x000d605e      488d742470     lea rsi, qword [rsp + 0x70] ; 0x70 ; sym.data.8589 ; sym.data.8589
{% endhighlight %}

That's it we have found the magic gadget:
{% highlight shell-session %}
[0x00020830]> pd 4 @0x000d605e
|           0x000d605e      488d742470     lea rsi, qword [rsp + 0x70] ; 0x70 ; sym.data.8589 ; sym.data.8589
|           0x000d6063      488d3d80e008.  lea rdi, qword [rip + 0x8e080] ; 0x1640ea ; hit0_0 ; "/bin/sh" @ 0x1640ea
|           0x000d606a      488b10         mov rdx, qword [rax]
|           0x000d606d      e8be19feff     call sym.__GI_execve
{% endhighlight %}

The address `0x000d605e` is the offset of the magic gadget. To have the real
address one has to find the base address at which the libc is loaded (e.g. by
using `vmmstat` in GDB).

If you are curious and want to see what is done by the function `execve`:
{% highlight shell-session %}
[0x00020830]> pdf @sym.__GI_execve
            ;-- __GI___execve:
            ;-- __execve:
            ;-- execve:
/ (fcn) sym.__GI_execve 33
|           ; XREFS: JMP 0x000b7b2a  CALL 0x0003f4c4  CALL 0x000d606d  CALL 0x000d9a9a  CALL 0x000d9d75  
|           ; XREFS: CALL 0x000da033  CALL 0x000b823e  CALL 0x000b82d3  CALL 0x000b805b  CALL 0x000b8141  
|           ; XREFS: CALL 0x000b7e78  CALL 0x000b7dfe  CALL 0x000b7c59  CALL 0x000b7ab3  
|           0x000b7a30      b83b000000     mov eax, 0x3b               ; section_end..gnu.warning.inet6_option_find
|           0x000b7a35      0f05           syscall
|           0x000b7a37      483d01f0ffff   cmp rax, -0xfff
|       ,=< 0x000b7a3d      7301           jae 0xb7a40                
|       |   0x000b7a3f      c3             ret
|       |   ; JMP XREF from 0x000b7a3d (sym.__GI_execve)
|       `-> 0x000b7a40      488b0d19342e.  mov rcx, qword [rip + 0x2e3419] ; [0x39ae60:8]=0
|           0x000b7a47      f7d8           neg eax
|           0x000b7a49      648901         mov dword fs:[rcx], eax
|           0x000b7a4c      4883c8ff       or rax, 0xffffffffffffffff
\           0x000b7a50      c3             ret
{% endhighlight %}

We can see that `rax` is set with 59 followed by the `syscall` instruction.

That example showed to magic gadget of the latest libc available in Arch Linux (glibc 2.23-1).
Here it is for the latest Ubuntu 14.04 (libc6 2.19-0ubuntu6.7):
{% highlight shell-session %}
[0x00021fd0]> pd 7 @0x0004652e
|           0x0004652e      0575793700     add eax, 0x377975
|           0x00046533      488d3da16713.  lea rdi, qword [rip + 0x1367a1] ; 0x17ccdb ; hit0_0 ; "/bin/sh" @ 0x17ccdb
|           0x0004653a      488d742430     lea rsi, qword [rsp + 0x30] ; 0x30 ; section_end..gnu.warning.fdetach ; section_end..gnu.warning.fdetach
|           0x0004653f      c70577a13700.  mov dword [rip + 0x37a177], 0 ; [0x3c06c0:4]=32
|           0x00046549      c7057da13700.  mov dword [rip + 0x37a17d], 0 ; [0x3c06d0:4]=4
|           0x00046553      488b10         mov rdx, qword [rax]
|           0x00046556      e8d5ad0700     call sym.execve
{% endhighlight %}

Happy pwning!

[radare2]: http://www.radare.org/r/
[r2techorganic]: http://blog.techorganic.com/2016/03/08/radare-2-in-0x1e-minutes/
[r2dl]: http://www.radare.org/r/down.html
[r2git]: https://github.com/radare/radare2
[execve]: http://man7.org/linux/man-pages/man2/execve.2.html
[syscall]: http://man7.org/linux/man-pages/man2/syscall.2.html
