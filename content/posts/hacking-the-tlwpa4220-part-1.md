---
title: "Hacking the TL-WPA4220, Part 1: Laying the Ground"
date: 2020-11-14T22:46:04+01:00
tags: [embedded, TP-Link]
---

This is the first part of a series of 4 blog posts on the process I followed to discover two command injection vulnerabilities and a buffer overflow in TP-Link's TL-WPA4220, a Powerline adapter and WiFi extender. In this post, however, **we are not going to talk about the TL-WPA4220 at all**, but we will be looking at a vulnerability affecting version 5 of the TL-WA850RE WiFi Range extender that was [published a couple of years ago](https://medium.com/advisability/the-in-security-of-the-tp-link-technologies-tl-wa850re-wi-fi-range-extender-26db87a7a0cc).

The main goal of this series is to provide a detailed description of how I started from understanding an exploit affecting a given device to later apply this knowledge to find similar vulnerabilities (that were not previously reported) in another device. I will try to provide many details so that it can be followed along by a wide audience, even if they have no prior experience analyzing firmware.

## TL-WA850RE Revisited

As we mentioned above, in this post **we will focus on a particular vulnerability affecting TP-Link's WiFi Range extender TL-WA850RE**. Why this device and this vulnerability? Well, mainly because when I first started to play with the TL-WPA4220 that I had just bought, I thought maybe there was *already* some vulnerability disclosed in the past. However, googling it did not bring up any result about this device, but it did return [some](https://medium.com/advisability/the-in-security-of-the-tp-link-technologies-tl-wa850re-wi-fi-range-extender-26db87a7a0cc) [results](https://www.refirmlabs.com/firmware-vulnerability-detection/) on the TL-WA850RE. Since it has similar functionality (in the end, it is also a WiFi extender) and also has an HTTP interface, I thought it would be interesting to give it a look before proceeding with the TL-WPA4220. And indeed, it was!

When examining already known vulnerabilities for which the exploit is public, we can start by looking carefully at the exploit code to get an idea of what it does and what vulnerability could be behind. In this case, [the code](https://www.exploit-db.com/exploits/44912) is pretty easy to understand. We see the following:
- First, a login request is done (with a username and password provided as arguments).
- After that, a POST request is made to the endpoint `/data/wps.setup.json` passing the following data:
```python
[
    ("operation", "write"),
    ("option", "connect"),
    ("wps_setup_pin", "11480723;telnetd -l /bin/sh"),
]
```
That is, for the exploit to work, the parameter `operation` must have the value `write` and the parameter `option` the value `connect`. Moreover, **it seems pretty clear that the vulnerable parameter is `wps_setup_pin`**, since the value contains a PIN number followed by a semi-colon and a command that spawns the telnet daemon. Also, that makes us think that when the device receives such a request, it will take the value of the `wps_setup_pin` parameter and pass it as an argument to a system utility without escaping or sanitizing it. The command shell will interpret the semi-colon as a separator between two commands, so it will execute the second part as an independent command, allowing the attacker to spawn the telnet daemon, for example. In other words, **it looks like we are dealing with a command injection vulnerability**.

Once we have a generic idea of what we might be dealing with, the next step is reverse-engineering the vulnerable binary and locating the vulnerability. Note that with the information that we have already gathered, the search can be narrowed down a lot. As a summary, here is what we know for now:
- The vulnerability seems to exist in the HTTP server (so we will have to analyze the binary `httpd`, and we can forget about any other binary)
- The vulnerability is a command injection, which is way easier to identify at first sight than other types of vulnerabilities such as a buffer overflow
- The vulnerable endpoint is `/data/wps.setup.json`, so we have to understand what happens when this endpoint is called

## Extracting the Firmware

To obtain the `httpd` binary, first we should download [a vulnerable version of the firmware](https://static.tp-link.com/2017/201712/20171222/TL-WA850RE_V5_171218.zip). After extracting the contents of the ZIP file, we can extract the firmware with `binwalk`:

```bash
$ binwalk -e 850rev5-up-ver1-0-0-P1\[20171218-rel58240\].bin

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8212          0x2014          TP-Link firmware header, firmware version: 0.0.0, image version: "", product ID: 0x0, product version: 0, kernel load address: 0x0, kernel entry point: 0x80, kernel offset: 0, kernel length: 512, rootfs offset: 869987, rootfs length: 0, bootloader offset: 0, bootloader length: 0
8724          0x2214          LZMA compressed data, properties: 0x5D, dictionary size: 33554432 bytes, uncompressed size: 2503344 bytes
878712        0xD6878         Squashfs filesystem, little endian, version 4.0, compression:xz, size: 2847680 bytes, 556 inodes, blocksize: 131072 bytes, created: 2017-12-18 08:10:38
```

We see the Squashfs filesystem, which indicates that the operating system of the device is Linux. We can see its contents in the folder `squashfs-root` that has been extracted by `binwalk`. The `httpd` binary is in the directory `squashfs-root/usr/bin`, and we see that it is a MIPS executable:
```bash
$ file squashfs-root/usr/bin/httpd
squashfs-root/usr/bin/httpd: ELF 32-bit LSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), dynamically linked, interpreter /lib/ld-uClibc.so.0, stripped
```

After that, we can analyze `httpd` with Ghidra. Since the binary is stripped (like one would expect), most of the variables and functions will have meaningless names generated automatically by Ghidra. In the following, I have decided not to rename any of these variables and functions so that if the reader decides to analyze the binary with Ghidra themselves, they would see exactly the same as what is shown here. Note that there are some functions that *do* have meaningful names (such as `httpWpsInit`, `execFormatCmd`, etc.). These names have not been defined by me: these functions are exports of the binary, so this information is present in the binary itself.

## Analyzing `httpd`

Our first goal is to **determine where the string `/data/wps.setup.json` is used**. Since we know that this is the vulnerable endpoint, we want to know what parts of the code are executed when it is accessed. Then, we will start looking at these parts and from there we will try to track down the vulnerability. This is much more effective than trying to understand the whole binary, which would probably take us some days at least.

We can find the uses of this string by clicking on the Window menu, selecting "Defined Strings", and writing it in the Filter textbox. Then we double-click on the result, and in the disassembly view we can search for the cross-references right-clicking on the variable (or simply pressing `Ctrl+Shift+F`). Doing that we see that this string is only referenced at the address `0x00429930`, which is inside the function `httpWpsInit`. The decompilation of this function is:

![httpWpsInit](/img/hacking-the-tlwpa4220-part-1/httpWpsInit.png "Decompilation of the function httpWpsInit")

We see that the function `httpRpmConfAddAndRegisterFile` is called, passing the endpoint as a parameter. The name of the function suggests that it is configuring how the HTTP server will respond when this endpoint is accessed. We can also see that the third parameter is a function (in our case, `FUN_00429750`), probably the function that will be called when this endpoint is accessed. Taking a look at `FUN_00429750`, we see the following (we show only an excerpt of the decompiled function):

![FUN_00429750](/img/hacking-the-tlwpa4220-part-1/FUN_00429750.png "Decompilation of the function FUN_00429750")

The `httpGetEnv` function seems to obtain the value of the specified HTTP parameter, in this case the parameter `operation`. This is stored in a variable that Ghidra names `__s1`, and then compared to the string `write`. If they are equal, the function `FUN_00429610` will be called.

Recall that, in the exploit, the first parameter was precisely `operation` with the value `write`, so the execution flow of the exploit will go through this path. So let's decompile the function `FUN_00429610` and try to understand what it does:

![FUN_00429610](/img/hacking-the-tlwpa4220-part-1/FUN_00429610.png "Decompilation of the function FUN_00429610")

Here we can see the following:
- First (highlighted with blue boxes), the value of the POST parameter `option` is retrieved (again with the function `httpGetEnv`) and stored in the variable `__s1`. This will be compared to the string `connect` (which is the value that the parameter `option` has in the exploit).
- Secondly (highlighted with red boxes), if the value of `__s1` is indeed equal to `connect`, the value of the POST parameter `wps_setup_pin` is retrieved and stored again in `__s1`. If it is not empty, this value will be copied in the variable named `acStack24`, which will be used as the second argument in the call of the function `execFormatCmd`.

From the name of this function and the first parameter (that contains the format string `%s`), we can infer that ultimately the following will be executed:
```bash
wps_cli -s --pin <contents of acStack24>
```

Let's see if our instincts are correct!

## Finding the Vulnerability

A quick look at the function `execFormatCmd` seems to confirm our suspicions:

![execFormatCmd](/img/hacking-the-tlwpa4220-part-1/execFormatCmd.png "Decompilation of the function execFormatCmd")

Indeed, we can see that this function calls `vsprintf` and stores the result in `acStack268`. With the above parameters this variable would have the following value:
```bash
wps_cli -s --pin <contents of acStack24>
```
as we guessed. This variable is then passed to `FUN_0040b090`, where presumably this will be executed. Looking at this function, the following part stands out:

![FUN_0040b090](/img/hacking-the-tlwpa4220-part-1/FUN_0040b090.png "Decompilation of the function FUN_0040b090")

First, we see that the function `fork` is called, creating a child process. This process, identified by the value of `__pid` being zero, constructs a null-terminated array of pointers to strings (starting at address `local_2c`). Indeed, looking at the information provided by Ghidra at the start of the function's disassembly, we can see that although the variables `local_2c`, `local_28`, `local_24` and `local_20` seem independent, they are actually allocated contiguously in the stack (with four bytes of space for each one):

![locals-def](/img/hacking-the-tlwpa4220-part-1/locals-def.png "Local variables in the stack")

Also, inspecting the global variable `DAT_0048a50c`, we see that it is the string `-c`. Therefore, the variable stored at address `local_2c` can be "visualized" as the following array:
```bash
[ "sh", "-c", local_18]
```
Note that here, `local_18` is just the parameter passed to the function (in our case, the variable `acStack268` described above). This array is then passed as the parameter `argv` of the function `execve`, which has `/bin/sh` as the first parameter. In other words, the following will be executed:
```bash
/bin/sh -c <contents of local_18>
```
Note that the first element of the array (`sh`) corresponds to `argv[0]`, which is simply the name of the executable and is not actually passed as an argument to `/bin/sh`.

It seems, thus, that we found the root of the issue. When we set `local_18` to be:
```bash
wps_cli -s --pin 12;telnetd -l /bin/sh
```
the following will be executed:
```bash
/bin/sh -c wps_cli -s --pin 12;telnetd -l /bin/sh
```
As we mentioned above, the semi-colon is interpreted as a separator between two commands, so this is equivalent to executing:
```bash
/bin/sh -c wps_cli -s --pin 12
telnetd -l /bin/sh
```

Great! We successfully hunted down the vulnerability and completely understood why and how it could be exploited. In the subsequent posts, we will make use of this knowledge to find similar vulnerabilities in the TL-WPA4220 Powerline WiFi extender.

## Conclusions

Before wrapping up, let's take a moment to sum up what we have seen in this post. First of all, we started by looking at an exploit for TP-Link's TL-WA850RE. The exploit was fairly easy to understand and gave us an idea of where the vulnerability could be (in the `httpd` binary, when a certain endpoint was called with specific POST parameters).

After that, we extracted the firmware with `binwalk` and proceeded to analyze the `httpd` binary. **Our analysis was mainly guided by the information that we gathered from the exploit** (looking only at the affected endpoint and following the path taking into account the POST parameters that the exploit passed). This allowed us to reach the root of the vulnerability, where we could see that a user-provided string was passed as part of a command executed using `/bin/sh` without any kind of escaping or sanitization. During this process, the decompilation done by Ghidra has been of great help, producing C-like code from the disassembly, which was really easy to analyze.

As we already mentioned, the goal of this post is not to present anything new (the vulnerability and exploit have been known for many years), but to **take this previous knowledge and understand it completely**, so that we can benefit from this learning. When we proceed to analyze the TL-WPA4220, a good starting point can be to look for similar vulnerabilities, since often the vendors reuse code and programming patterns. In particular, we can start by looking if the function `execFormatCmd` is also present and, if so, determine whether in any of its calls there is a user-supplied parameter. This would be a great candidate to find a command injection vulnerability like the one we have just seen.

If you are curious to see how this story continues, head to [part two](/posts/hacking-the-tlwpa4220-part-2/) of this series!
