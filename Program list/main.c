#include <windows.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <stdio.h>
#include <string.h>
#include <tchar.h>
#include <inttypes.h>
#include <io.h>  

#pragma warning(disable:4996)
#pragma comment(lib, "ws2_32.lib")

#define BUFSIZE 1024
#define MD5LEN  16
#define SERVER "127.0.0.1"
#define PORT 8001
#define MAX_THREADS 2


DWORD WINAPI getDataFromServer(LPVOID lpParam);
DWORD WINAPI GetProcessList(LPVOID lpParam);

HWND GetWinHandle(ULONG pid);
ULONG ProcIDFromWnd(HWND hwnd);
BOOL ListProcessModules(DWORD, BOOL );
BOOL ListProcessThreads(DWORD, BOOL);
BOOL KillProcess(DWORD);
char* getName(char* def);

BOOL isBlockHash(char*);
BOOL isBlockName(char*);
BOOL isBlockClass(char*);

char* GetMD5(LPCWSTR);
void printError(const wchar_t*);

int main()
{
	DWORD dwThreadIDArray[MAX_THREADS];
	HANDLE hThreadArray[MAX_THREADS];
	hThreadArray[0] = CreateThread(NULL, 0, GetProcessList, NULL, 0, &dwThreadIDArray[0]);
	if (hThreadArray[0] == NULL)
		printError(TEXT("CreateThread() Error!"));

	hThreadArray[1] = CreateThread(NULL, 0, getDataFromServer, NULL, 0, &dwThreadIDArray[1]);
	if (hThreadArray[1] == NULL)
		printError(TEXT("CreateThread() Error!"));

	WaitForMultipleObjects(MAX_THREADS, hThreadArray, TRUE, INFINITE);
	for (int i = 0; i < MAX_THREADS; i++)
		CloseHandle(hThreadArray[i]);
}

DWORD WINAPI getDataFromServer(LPVOID lpParam) {
	while (1) {
		WSADATA wsaData;
		SOCKET hSocket;
		SOCKADDR_IN servAddr;
		char message[3];
		int strLen;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		{
			printError(TEXT("WSAStartup(), error"));
		}

		// 서버 접속을 위한 소켓 생성
		hSocket = socket(PF_INET, SOCK_STREAM, 0);
		if (hSocket == INVALID_SOCKET)
		{
			printError(TEXT("hSocketet(), error"));
		}
		memset(&servAddr, 0, sizeof(servAddr));
		servAddr.sin_family = AF_INET;
		servAddr.sin_addr.s_addr = inet_addr(SERVER);
		servAddr.sin_port = htons(PORT);
		// 서버로 연결 요청
		if (connect(hSocket, (SOCKADDR*)&servAddr, sizeof(servAddr)) == SOCKET_ERROR)
		{
			printError(TEXT("Connect() error"));
		}

		for (int i = 0; i < 3; i++) {
			FILE* fp;
			switch (i) {
			case 0:
				fp = fopen("ClassID.txt", "rb");
				break;
			case 1:
				fp = fopen("ProcessName.txt", "rb");
				break;
			case 2:
				fp = fopen("Hash.txt", "rb");
				break;
			default: break;
			}
			char* servlen = (char*)calloc(64, 1);
			if (fp == NULL){
				servlen[0] = '0';
		  } else {
				fseek(fp, 0, SEEK_END);

				itoa(ftell(fp), servlen, 10);
			}
			int test = send(hSocket, servlen, 64, 0);
			// 데이터 수신
			strLen = recv(hSocket, message, 3, 0);
			if (strLen == -1) {
				printError(TEXT("Fail recv from server...\n"));
			}
			else {
				if (strncmp(message, "OK", 2) == 0) {
					printf("OK!\n");
				}
				else {
					if(fp != NULL)
							fclose(fp);
					switch (i) {
					case 0:
						fp = fopen("ClassID.txt", "w+");
						break;
					case 1:
						fp = fopen("ProcessName.txt", "w+");
						break;
					case 2:
						fp = fopen("Hash.txt", "w+");
						break;
					default: break;
					}
					char* len = (char*)calloc(64, 1);
					recv(hSocket, len, 64, 0);
					char* temp = (char*)calloc(atoi(len), 1);
					recv(hSocket, temp, atoi(len), 0);
					fwrite(temp, sizeof(char), atoi(len), fp);
					free(temp);
					free(servlen);
					free(len);
				}
			}
			fclose(fp);
			printf("Message from server : %s \n", message);
		}
		// 연결 종료
		closesocket(hSocket);
		WSACleanup();
		Sleep(1000 * 60 * 2);
	}
	return 1;
}

char* getName(char* def) {
	int i = 0;
	int size = 0;
	char *temp_def = def;

	while (*temp_def != 0x00) {
		size++;
		temp_def += 2;
	}

	char* temp = (char*)calloc(size+1, 1);

	while (*def != 0x00) {
		temp[i] = *def;
		def += 2;
		i++;
	}

	return temp;
}
DWORD WINAPI GetProcessList(LPVOID lpParam) {
	while (1) {
		HANDLE hProcessSnap;
		HANDLE hProcess;
		PROCESSENTRY32 pe32;
		DWORD dwPriorityClass;

		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) {
			printError(TEXT("CreateToolhelp32Snapshot (of processes)"));
			return(FALSE);
		}

		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (!Process32First(hProcessSnap, &pe32)) {
			printError(TEXT("Process32First"));
			CloseHandle(hProcessSnap);
			return(FALSE);
		}

		do {
			_tprintf(TEXT("\n\n====================================================="));
			_tprintf(TEXT("\nPROCESS NAME:  %s"), pe32.szExeFile);
			_tprintf(TEXT("\n-------------------------------------------------------"));
			
			char *name = getName(pe32.szExeFile);

			BOOL kill = isBlockName(name);
			dwPriorityClass = 0;
			hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			if (hProcess == NULL)
				printError(TEXT("OpenProcess"));
			else {
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
			ListProcessModules(pe32.th32ProcessID, kill);
			ListProcessThreads(pe32.th32ProcessID, kill);

			free(name);
		} while (Process32Next(hProcessSnap, &pe32));

		CloseHandle(hProcessSnap);
		Sleep(1000 * 60 * 2);
	}
	return(TRUE);
}

BOOL ListProcessModules(DWORD dwPID, BOOL isKill) {
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hModuleSnap == INVALID_HANDLE_VALUE) {
		printError(TEXT("CreateToolhelp32Snapshot (of modules)"));
		return(FALSE);
	}
	me32.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hModuleSnap, &me32)) {
		printError(TEXT("Module32First"));
		CloseHandle(hModuleSnap);
		return(FALSE);
	}
	do {	
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     Executable     = %s"), me32.szExePath);
		char* md5 = GetMD5(me32.szExePath);
		printf("\n     MD5              = %s", md5);
		char * className = (char*)calloc(256, sizeof(char));
		GetClassName(GetWinHandle(me32.th32ProcessID), className, 256);
		if (isBlockClass(className) | isKill| isBlockHash(md5)) {
			KillProcess(me32.th32ProcessID);
			free(md5);
			free(className);
			continue;
		}
		_tprintf(TEXT("\n     Class     = %s"), className);
		_tprintf(TEXT("\n     Process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     Ref count (g)  = 0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     Ref count (p)  = 0x%04X"), me32.ProccntUsage);
		_tprintf(TEXT("\n     Base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf(TEXT("\n     Base size      = %d"), me32.modBaseSize);
		free(md5);
		free(className);
	} while (Module32Next(hModuleSnap, &me32));

	CloseHandle(hModuleSnap);
	return(TRUE);
}

BOOL isBlockName(char* name) {
		FILE* fp = fopen("ProcessName.txt", "rb");
		char temp[256] = { 0, };
		if (fp == NULL)
			return(FALSE);
		while (!feof(fp)) {
			fscanf(fp, "%s", temp);
			if (strncmp(temp, name, strlen(temp) - 1) == 0) {
				fclose(fp);
				return (TRUE);
			}
		}
		fclose(fp);
		return (FALSE);
}

BOOL isBlockHash(char* md5) {
	FILE* fp = fopen("Hash.txt", "rb");
	char temp[256] = { 0, };
	if (fp == NULL)
		return(FALSE);
	while (!feof(fp)) {
		fscanf(fp, "%s", temp);
		if (strncmp(temp, md5, strlen(temp) - 1) == 0) {
			fclose(fp);
			return (TRUE);
		}
	}
	fclose(fp);
	return (FALSE);
}

BOOL isBlockClass(char* className) {
	FILE* fp = fopen("ClassID.txt", "rb");
	char temp[256] = { 0, };
	if (fp == NULL)
		return(FALSE);
	while (!feof(fp)) {
		fscanf(fp, "%s", temp);
		if (strncmp(temp, className, strlen(temp) - 1) == 0) {
			fclose(fp);
			return (TRUE);
		}
	}
	fclose(fp);
	return (FALSE);
}

ULONG ProcIDFromWnd(HWND hwnd) {
	ULONG idProc;
	GetWindowThreadProcessId(hwnd, &idProc);
	return idProc;
}

HWND GetWinHandle(ULONG pid) {
	HWND tempHwnd = FindWindow(NULL, NULL); // 최상위 윈도우 핸들 찾기   
	while (tempHwnd != NULL)
	{
		// 최상위 핸들인지 체크, 버튼 등도 핸들을 가질 수 있으므로 무시하기 위해
		if (GetParent(tempHwnd) == NULL) {
			if (pid == ProcIDFromWnd(tempHwnd))
				return tempHwnd;
		}
		tempHwnd = GetWindow(tempHwnd, GW_HWNDNEXT); // 다음 윈도우 핸들 찾기   
	}
	return NULL;
}

BOOL ListProcessThreads(DWORD dwOwnerPID, BOOL kill) {
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	THREADENTRY32 te32;

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
		return(FALSE);

	te32.dwSize = sizeof(THREADENTRY32);

	if (!Thread32First(hThreadSnap, &te32)) {
		printError(TEXT("Thread32First"));
		CloseHandle(hThreadSnap);
		return(FALSE);
	}

	do
	{
		if (kill)
			KillProcess(te32.th32ThreadID);
		/*if (te32.th32OwnerProcessID == dwOwnerPID)
		{
		_tprintf(TEXT("\n\n     THREAD ID      = 0x%08X"), te32.th32ThreadID);
		_tprintf(TEXT("\n     Base priority  = %d"), te32.tpBasePri);
		_tprintf(TEXT("\n     Delta priority = %d"), te32.tpDeltaPri);
		_tprintf(TEXT("\n"));
		}*/
	} while (Thread32Next(hThreadSnap, &te32));

	CloseHandle(hThreadSnap);
	return(TRUE);
}

//pid, exit code[1]
BOOL KillProcess(DWORD dwProcessId) {
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
void printError(const wchar_t* msg) {
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

	//exit(EXIT_FAILURE);
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

	if (INVALID_HANDLE_VALUE == hFile) {
		dwStatus = GetLastError();
		printf("Error opening file %s\nError: %d\n", filename,
			dwStatus);
		return (char*)dwStatus;
	}

	if (!CryptAcquireContext(&hProv,
		NULL,
		NULL,
		PROV_RSA_FULL,
		CRYPT_VERIFYCONTEXT)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		return  (char*)dwStatus;
	}

	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		dwStatus = GetLastError();
		printf("CryptAcquireContext failed: %d\n", dwStatus);
		CloseHandle(hFile);
		CryptReleaseContext(hProv, 0);
		return  (char*)dwStatus;
	}

	while (bResult = ReadFile(hFile, rgbFile, BUFSIZE,
		&cbRead, NULL)) {
		if (0 == cbRead)
			break;

		if (!CryptHashData(hHash, rgbFile, cbRead, 0)) {
			dwStatus = GetLastError();
			printf("CryptHashData failed: %d\n", dwStatus);
			CryptReleaseContext(hProv, 0);
			CryptDestroyHash(hHash);
			CloseHandle(hFile);
			return  (char*)dwStatus;
		}
	}

	if (!bResult) {
		dwStatus = GetLastError();
		printf("ReadFile failed: %d\n", dwStatus);
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		CloseHandle(hFile);
		return (char*)dwStatus;
	}
	char* result = (char*)calloc(BUFSIZE, sizeof(char));
	cbHash = MD5LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		//printf("MD5 hash of file %s is: ", filename)
		DWORD i;
		for (i = 0; i < cbHash; i++) {
			char CH = rgbDigits[rgbHash[i] >> 4];
			char CL = rgbDigits[rgbHash[i] & 0xf];
			sprintf(result, "%s%c%c", result, CH, CL);
			//printf("%c%c", rgbDigits[rgbHash[i] >> 4], rgbDigits[rgbHash[i] & 0xf]);
		}
	}
	else {
		dwStatus = GetLastError();
		printf("CryptGetHashParam failed: %d\n", dwStatus);
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return result;
}