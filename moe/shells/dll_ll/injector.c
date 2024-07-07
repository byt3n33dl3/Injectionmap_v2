#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#define TARGET "notepad.exe"
#define DLL_PATH "C:\\Users\\whokilleddb\\Codes\\injection-for-dummies\\dll_ll\\injectme.dll"
#define IS_HANDLE_INVALID(x) (x==NULL || x==INVALID_HANDLE_VALUE)

// Find PID from a Process Name
DWORD find_pid(const char* procname) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32;
    
    // Take Snapshot of all processes on the system
    // See: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    HANDLE hProcSnap = CreateToolhelp32Snapshot(
        TH32CS_SNAPPROCESS, //  Take a snapshot of the processes
        0                   //  Capture a snapshot of all processes in the system
    );

    // Check if handle is valid
    if (IS_HANDLE_INVALID(hProcSnap)) {
        fprintf(stderr, "[!] CreateToolhelp32Snapshot() failed (0x%x)\n", GetLastError());
        return 0;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);   // Store size of strcut

    // Retrieves information about the first 
    // process encountered in a system snapshot.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    BOOL result = Process32First(hProcSnap, &pe32);

    if (!result) {
        fprintf(stderr, "[!] Process32First() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcSnap);
        return 0;
    }

    // Loop through Snapshot entries
    while (Process32Next(hProcSnap, &pe32)) {
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    CloseHandle(hProcSnap);
    return pid;
}

// DLL Inject into Process
int inject_dll_ll(DWORD pid) {
    printf("[i] Injecting DLL: %s\n", DLL_PATH);

    // Open handle to another process
	HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,         // Process permissions
        FALSE,                      // Do not inherit handles 
        pid                         // PID of remote process
    );
    
    // Check handle version
    if (IS_HANDLE_INVALID(hProcess)) {
        fprintf("[!] OpenProcess() failed (0x%x)\n", GetLastError());
        return -2;
    }
    // Resolve LoadLibrary
    // Get a Handle to Kernel32.dll
    HMODULE hModule = GetModuleHandle("Kernel32.dll");
    if (IS_HANDLE_INVALID(hModule)) {
        fprintf(stderr, "[!] GetModuleHandle() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // Find address to LoadLibrary
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE) GetProcAddress(hModule, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        fprintf(stderr, "[!] GetProcAddress() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // Close handle as it is not required anymore
    CloseHandle(hModule); 

    // Allocate Memory to store DLL Path
    PVOID pAddr = VirtualAllocEx(
        hProcess,
        NULL, 
        sizeof(DLL_PATH), 
        MEM_COMMIT, 
        PAGE_READWRITE
    );

    if (pAddr == NULL) {
        fprintf(stderr, "[!] VirtualAllocEx() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    BOOL result = WriteProcessMemory(
        hProcess, 
        pAddr, 
        (LPVOID)DLL_PATH, 
        sizeof(DLL_PATH), 
        NULL
    );

    if (!result) {
        fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    HANDLE hThread = CreateRemoteThread(
        hProcess, 
        NULL, 
        0, 
        pLoadLibrary, 
        pAddr, 
        0, 
        NULL
    );
    
    if (IS_HANDLE_INVALID(hThread)) {
        fprintf(stderr, "[!] CreateRemoteThread() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    int _result =  WaitForSingleObject(hThread, -1);
    if (_result == WAIT_FAILED) {
        fprintf(stderr, "[!] WaitForSingleObject() failed (0x%x) with code 0x%x\n", GetLastError(), _result);
        CloseHandle(hThread);    
        CloseHandle(hProcess);
        return -1;
    } 

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

int main() {
	DWORD pid = find_pid(TARGET);
	if ( pid == 0) {
		fprintf(stderr, "[!] No %s found\n", TARGET);
        return -1;
	}

	printf("[i] %s: %d\n", TARGET, pid);

    int result = inject_dll_ll(pid);
    if (result < 0) {
        fprintf(stderr, "[!] Injection failed\n");
        return -1;
    }

    printf("[i] Injection Complete!\n");
    return 0;
}