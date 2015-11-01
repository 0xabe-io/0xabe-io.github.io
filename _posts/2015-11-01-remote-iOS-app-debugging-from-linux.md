---
layout: post
title:  "Remote iOS application debugging from Linux over USB"
date:   2015-11-01 20:00:00
categories: howto iOS debug
---
I recently had to debug an iOS application. As I am more a GNU/Linux user than an
OS X one, I wanted to do it from my Linux machine. The easiest way would be to
remotely debug over WiFi, but this might get quite frustrating, because of the
recurring connection interruptions. Good news everyone: it is possible to do it
over USB!

Here is what you need:

* a jailbroken iOS device (I used an iOS 9.0.2 one) with OpenSSH isntalled
* an OS X installation with Xcode for the `debugserver` (iOS equivalent of
  `gdbserver`)
* that fancy USB proprietary cable
* your favorite Linux installation

#Getting debugserver

This part is taken from that [guide][debugserver]. 

Once your iOS device is jailbroken with OpenSSH installed, it is time to go on
your OS X installation to prepare `debugserver` which is sort of an iOS
application equivalent of `gdbserver`. The Xcode application has developer disk
images for the supported iOS version:

{% highlight shell-session %}
$ ls /Applications/Xcode.app/Contents/Developer/Platforms/\
  iPhoneOS.platform/DeviceSupport/
6.0	6.1	7.0	7.1	8.0	8.1
8.2	8.3	8.4	9.0	9.1 (13B137)
{% endhighlight %}

Choose the one corresponding to the version of your jailbroken device. For
example with a jailbroken iOS 9.0.2:
{% highlight shell-session %}
$ hdiutil attach /Applications/Xcode.app/Contents/Developer/Platforms/\
  iPhoneOS.platform/DeviceSupport/9.0/DeveloperDiskImage.dmg
{% endhighlight %}

It should be mounted to `/Volumes/DeveloperDiskImage`

Copy `debugserver`:
{% highlight shell-session %}
$ mkdir debugserver
$ cd debugserver
$ cp /Volumes/DeveloperDiskImage/usr/bin/debugserver .
{% endhighlight %}

You can now unmount the developer disk image:
{% highlight shell-session%}
$ hdiutil detach /Volumes/DeveloperDiskImage/
{% endhighlight %}

Create the `entitlements.plist` file that will be used to resign the `debugserver`:
{% highlight shell-session %}
$ cat << EOF > entitlements.plist
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"> 
  <dict> 
    <key>com.apple.springboard.debugapplications</key> 
    <true/> 
    <key>run-unsigned-code</key> 
    <true/> 
    <key>get-task-allow</key> 
    <true/> 
    <key>task_for_pid-allow</key> 
    <true/> 
  </dict> 
</plist>
EOF
{% endhighlight %}

Resign the `debugserver`:
{% highlight shell-session %}
$ codesign -s - --entitlements entitlements.plist -f debugserver
{% endhighlight %}

And finally copy the newly signed `debugserver` to your Linux machine (e.g. with SSH).

#Preparing the Linux host

I mentioned that `debugserver` is an iOS application equivalent to the
`gdbserver`. It's not entirely true because it is not compatible with `gdb` but
with [`lldb`][lldb], the debugger of the [llvm][llvm] project.

For example on a Debian based distribution:
{% highlight shell-session %}
$ sudo apt-get install libusbmuxd-tools usbmuxd lldb
{% endhighlight %}

Or on an Archlinux:
{% highlight shell-session %}
$ sudo pacman -S --needed usbmuxd lldb
{% endhighlight %}

Launch `usbmuxd` service, for example with systemd:
{% highlight shell-session %}
$ sudo systemctl start usbmuxd.service
{% endhighlight %}

If your distribution doesn't use systemd, the package should come with an init
or upstart script that you can use to launch it.

Connect your jailbroken iOS device to your Linux host and create an SSH tunnel:
{% highlight shell-session %}
$ sudo iproxy 2222 22
{% endhighlight %}

Now you should be able to SSH to your iOS device through port 2222. If not
already done, you should change the default `alpine` root password now.
{% highlight shell-session %}
$ ssh root@localhost -p 2222
{% endhighlight %}

Back to your Linux machine, copy the `debugserver` to the iOS device:
{% highlight shell-session %}
$ scp -P 2222 debugserver root@localhost:/var/private/root/
{% endhighlight %}

Now everything is set to debug your favorite application.

#Finally debug something

To remotely debug an application, `debugserver` binds to a port so that you can
connect to it with `lldb`. Creating a tunnel with `iproxy` to that specific port
won't work, we have to create a proper SSH tunnel. With the previous tunnel
still active, create the SSH tunnel from the Linux machine:
{% highlight shell-session %}
$ ssh -L 12345:localhost:23456 root@localhost -p 2222
{% endhighlight %}

This means that any connection on port `12345` on localhost of the Linux
machine will be redirected to the port `23456` of the iOS device through the
tunnel.

On the iOS device, `debugserver` allows the following parrameters:
{% highlight shell-session %}
# ./debugserver 
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-340.3.51.1
 for arm64.
Usage:
 debugserver host:port [program-name program-arg1 program-arg2 ...]
 debugserver /path/file [program-name program-arg1 program-arg2 ...]
 debugserver host:port --attach=<pid>
 debugserver /path/file --attach=<pid>
 debugserver host:port --attach=<process_name>
 debugserver /path/file --attach=<process_name>
{% endhighlight %}

It can launch an application or attach to a running one and it listens either
on a Unix or TCP socket. In our case, we have to use a TCP socket.

Here is an example of `debugserver` attaching to process number `1844` and
listening on port `23456` for incoming connection from `lldb`:
{% highlight shell-session %}
# debugserver 127.0.0.1:23456 --attach=1844
debugserver-@(#)PROGRAM:debugserver  PROJECT:debugserver-340.3.51.1
 for arm64.
Attaching to process 1844...
Listening to port 23456 for a connection from 127.0.0.1...
Waiting for debugger instructions for process 1844.
{% endhighlight %}

Now on the Linux machine, with both tunnels still open, run `lldb` and attach
to the `debugserver`:
{% highlight shell-session %}
$ lldb
(lldb) process connect connect://127.0.0.1:12345
Process 1844 stopped
* thread #1: tid = 0xdcc0, 0x380f9130, stop reason = signal SIGSTOP
    frame #0: 0x380f9130
->  0x380f9130: pop    {r4, r5, r6, r8}
    0x380f9134: bx     lr
    0x380f9138: mov    r12, sp
    0x380f913c: push   {r4, r5, r6, r8}
(lldb) c
Process 1844 resuming
{% endhighlight %}

For those that like to add extra functionalities to their debugger, such as
[peda][peda] on `gdb`, there is [lisa][lisa] that seems to add similar
functionalities as [peda][peda] to `lldb`.

[debugserver]: https://hirschmann.io/remote-ios-debugging/
[lldb]: http://lldb.llvm.org/
[llvm]: http://llvm.org/
[peda]: https://github.com/longld/peda
[lisa]: https://github.com/ant4g0nist/lisa.py
