#include <windows.h>
#include <tlhelp32.h>
#include <tchar.h>
#include <inttypes.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>

#define BUFSIZE 1024
#define MD5LEN  16
#define SERVER "127.0.0.1"
#define PORT "9000"
BOOL GetProcessList();
BOOL ListProcessModules(DWORD);
BOOL ListProcessThreads(DWORD);
BOOL KillProcess(DWORD);
char* GetMD5(LPCWSTR);
void SocketRelease();
void printError(TCHAR*);

SOCKADDR_IN servAdr;
WSADATA wsaData;
SOCKET hSocket;

typedef struct g{
	char* exeName, *className, *md5;
} Game;

int main(void){
	//WSAStartup(MAKEWORD(2, 2), &wsaData);

	//hSocket = socket(PF_INET, SOCK_STREAM, 0);

	//memset(&servAdr, 0, sizeof(servAdr));
	//servAdr.sin_family = AF_INET;
	//servAdr.sin_addr.s_addr = inet_addr(SERVER);
	//servAdr.sin_port = htons(atoi(PORT));	
	Game game;
	//connect(hSocket, (SOCKADDR*)&servAdr, sizeof(servAdr));
	//recv(hSocket, game.className, 1024, 0);
	GetProcessList();	
	return 0;
}

BOOL GetProcessList(){
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE){
		printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
		return(FALSE);
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (!Process32First(hProcessSnap, &pe32)){
		printError(TEXT("Process32First")); 
		CloseHandle(hProcessSnap);         
		return(FALSE);
	}

	do	{
		_tprintf(TEXT("\n\n====================================================="));
		_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
		_tprintf(TEXT("\n-------------------------------------------------------"));

		dwPriorityClass = 0;
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (hProcess == NULL)
			printError(TEXT("OpenProcess"));
		else{
			dwPriorityClass = GetPriorityClass(hProcess);
			if (!dwPriorityClass)
				printError(TEXT("GetPriorityClass"));
			CloseHandle(hProcess);
		}
		
		_tprintf(TEXT("\n  Process ID        = 0x%08X"), pe32.th32ProcessID);
		_tprintf(TEXT("\n  Thread count      = %d"), pe32.cntThreads);
		_tprintf(TEXT("\n  Parent process ID = 0x%08X"), pe32.th32ParentProcessID);
		_tprintf(TEXT("\n  Priority base     = %d"), pe32.pcPriClassBase);
		_tprintf(TEXT("\n  Priority class    = %d"), dwPriorityClass);
		ListProcessModules(pe32.th32ProcessID);
		ListProcessThreads(pe32.th32ProcessID);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return(TRUE);
}

BOOL ListProcessModules(DWORD dwPID){
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE)	{
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return(FALSE);
	}
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32))	{
		printError(TEXT("Module32First"));  
		CloseHandle(hModuleSnap);           
		return(FALSE);
	}
	do	{
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
		printf("\n     MD5              = %s", GetMD5(me32.szExePath));
		char className[256] = { 0, };
		GetClassName(hModuleSnap, className, 256);
		_tprintf(TEXT("\n     Class     = %s"), className);
		_tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
		_tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf(TEXT("\n     Base size      = %d"), me32.modBaseSize);
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}



BOOL ListProcessThreads(DWORD dwOwnerPID){
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32))	{
		printError(TEXT("Thread32First")); 
		CloseHandle(hThreadSnap);         
		return(FALSE);
	}

	do
	{
		if (te32.th32OwnerProcessID == dwOwnerPID)
		{
			_tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
			_tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
			_tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
			_tprintf(TEXT("\n"));
		}
	} while (Thread32Next(hThreadSnap, &te32));
	
	CloseHandle(hThreadSnap);
	return(TRUE);
}

//pid, exit code[1]
BOOL KillProcess(DWORD dwProcessId){
	UINT uExitCode = 1;
	DWORD dwDesiredAccess = PROCESS_TERMINATE;
	BOOL  bInheritHandle = FALSE;
	HANDLE hProcess = OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
	if (hProcess == NULL)
		return FALSE;

	BOOL result = TerminateProcess(hProcess, uExitCode);

	CloseHandle(hProcess);

	return result;
}
void printError(TCHAR* msg){
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		sysMsg, 256, NULL);

	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}

char* GetMD5(LPCWSTR path) {
	DWORD dwStatus = 0;
	BOOL bResult = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = NULL;
	BYTE rgbFile[BUFSIZE];
	DWORD cbRead = 0;
	BYTE rgbHash[MD5LEN];
	DWORD cbHash = 0;
	CHAR rgbDigits[] = "0123456789abcdef";
	LPCWSTR filename = path;

	hFile = CreateFile(filename,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_FLAG_SEQUENTIAL_SCAN,
		NULL);

	if (INVALID_HANDLE_VALUE == hFile)	{
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", filename,
			dwStatus);
		return dwStatus;
	}

	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT))	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash))	{
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL))	{
		if (0 == cbRead)
			break;

		if (!CryptHashData(hHash, rgbFile, cbRead, 0)){
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return dwStatus;
		}
	}

	if (!bResult){
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return dwStatus;
	}
	char result[BUFSIZE] = { 0, };
	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0))	{
		//printf("MD5 hash of file %s is: ", filename)
	   DWORD i;
		for ( i = 0; i < cbHash; i++)	{
			char CH = rgbDigits[rgbHash[i] >> 4];
			char CL = rgbDigits[rgbHash[i] & 0xf];
			sprintf(result, "%s%c%c", result, CH, CL);
			printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}
	}else{
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return result;
}