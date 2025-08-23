#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <set>
#include <iostream>
#include <iomanip>
#include <memory>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

// ---- Minimal NT types / prototypes ----
typedef LONG NTSTATUS;
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemExtendedHandleInformation = 0x40
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID       Object;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   HandleValue;
    ULONG       GrantedAccess;
    USHORT      CreatorBackTraceIndex;
    USHORT      ObjectTypeIndex;
    ULONG       HandleAttributes;
    ULONG       Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

using pfnNtQuerySystemInformation = NTSTATUS(NTAPI*)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

// ---- Helpers ----
static bool EnablePrivilege(LPCWSTR name) {
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
    return ok && GetLastError() == ERROR_SUCCESS;
}

static std::wstring ToLower(std::wstring s) {
    for (auto& ch : s) ch = towlower(ch);
    return s;
}

static std::wstring GetProcessName(DWORD pid) {
    std::wstring name = L"<unknown>";
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) return name;

    wchar_t buf[MAX_PATH]{};
    if (GetProcessImageFileNameW(h, buf, MAX_PATH) > 0) {
        size_t pos = std::wstring(buf).find_last_of(L"\\/");
        name = (pos == std::wstring::npos) ? buf : std::wstring(buf).substr(pos + 1);
    }
    CloseHandle(h);
    return name;
}

static DWORD FindPidByName(const std::wstring& targetName) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    std::wstring needle = ToLower(targetName);

    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring exe = ToLower(pe.szExeFile);
            if (exe == needle) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static std::wstring AccessMaskToFlags(DWORD access) {
    struct Flag { DWORD bit; const wchar_t* name; };
    static const Flag flags[] = {
        { PROCESS_TERMINATE,              L"TERMINATE" },
        { PROCESS_CREATE_THREAD,          L"CREATE_THREAD" },
        { PROCESS_VM_OPERATION,           L"VM_OPERATION" },
        { PROCESS_VM_READ,                L"VM_READ" },
        { PROCESS_VM_WRITE,               L"VM_WRITE" },
        { PROCESS_DUP_HANDLE,             L"DUP_HANDLE" },
        { PROCESS_CREATE_PROCESS,         L"CREATE_PROCESS" },
        { PROCESS_SET_QUOTA,               L"SET_QUOTA" },
        { PROCESS_SET_INFORMATION,        L"SET_INFORMATION" },
        { PROCESS_QUERY_INFORMATION,      L"QUERY_INFORMATION" },
        { PROCESS_SUSPEND_RESUME,         L"SUSPEND_RESUME" },
        { PROCESS_QUERY_LIMITED_INFORMATION, L"QUERY_LIMITED_INFO" },
        { SYNCHRONIZE,                    L"SYNCHRONIZE" }
    };
    std::wstring out;
    for (const auto& f : flags) {
        if (access & f.bit) {
            if (!out.empty()) out += L"|";
            out += f.name;
        }
    }
    if (access == PROCESS_ALL_ACCESS) {
        if (!out.empty()) out += L"|";
        out += L"ALL_ACCESS";
    }
    if (out.empty()) out = L"0x" + std::to_wstring(access);
    return out;
}

static bool IsSuspiciousAccess(DWORD access) {
    const DWORD suspicious = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS;
    return (access & suspicious) != 0;
}

static void PopulateDefaultWhitelist(std::set<std::wstring>& wl) {
    wl.insert(L"csrss.exe");
    wl.insert(L"winlogon.exe");
    wl.insert(L"lsass.exe");
    wl.insert(L"services.exe");
    wl.insert(L"svchost.exe");
    wl.insert(L"explorer.exe");
    wl.insert(L"MsMpEng.exe");
    wl.insert(L"audiodg.exe");
    wl.insert(L"svchost.exe");          
    wl.insert(L"pwnadventure3.exe");    

}

int wmain(int argc, wchar_t* argv[]) {
    const std::wstring targetName = L"PwnAdventure3-Win32-Shipping.exe";
    bool closeHandles = (argc >= 2 && std::wstring(argv[1]) == L"--close");

    std::wcout << L"[+] Target process name: " << targetName << L"\n";
    if (closeHandles) std::wcout << L"[+] Close mode ENABLED\n";

    if (!EnablePrivilege(SE_DEBUG_NAME))
        std::wcerr << L"[!] Failed to enable SeDebugPrivilege\n";

    DWORD targetPid = FindPidByName(targetName);
    if (!targetPid) {
        std::wcerr << L"[!] Target not found\n";
        return 1;
    }

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) hNtdll = LoadLibraryW(L"ntdll.dll");
    auto NtQuerySystemInformation = reinterpret_cast<pfnNtQuerySystemInformation>(
        GetProcAddress(hNtdll, "NtQuerySystemInformation"));
    if (!NtQuerySystemInformation) {
        std::wcerr << L"[!] NtQuerySystemInformation not found\n";
        return 1;
    }

    ULONG bufSize = 1 << 20;
    std::unique_ptr<BYTE[]> buffer;
    NTSTATUS status;
    for (;;) {
        buffer.reset(new BYTE[bufSize]);
        ULONG retLen = 0;
        status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer.get(), bufSize, &retLen);
        if (NT_SUCCESS(status)) break;
        if (status == (NTSTATUS)0xC0000004L) { bufSize *= 2; continue; }
        std::wcerr << L"[!] NtQuerySystemInformation failed\n";
        return 1;
    }

    auto* info = reinterpret_cast<PSYSTEM_HANDLE_INFORMATION_EX>(buffer.get());
    ULONG_PTR total = info->NumberOfHandles;
    std::set<std::wstring> wl; PopulateDefaultWhitelist(wl);
    std::set<std::wstring> wlLower; for (auto& n : wl) wlLower.insert(ToLower(n));

    size_t hits = 0, closed = 0;
    DWORD currentPid = GetCurrentProcessId();

    for (ULONG_PTR i = 0; i < total; ++i) {
        const auto& h = info->Handles[i];
        DWORD ownerPid = (DWORD)h.UniqueProcessId;
        if (ownerPid == currentPid || ownerPid == targetPid) continue;

        HANDLE hOwner = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, ownerPid);
        if (!hOwner) continue;

        HANDLE dup = nullptr;
        if (!DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)h.HandleValue, GetCurrentProcess(), &dup,
            PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 0)) {
            CloseHandle(hOwner);
            continue;
        }

        DWORD pointedPid = GetProcessId(dup);
        if (pointedPid == targetPid) {
            std::wstring ownerName = ToLower(GetProcessName(ownerPid));
            
            

            bool whitelisted = wlLower.count(ownerName) > 0;
            bool suspicious = !whitelisted && IsSuspiciousAccess(h.GrantedAccess);

            std::wcout << L"[HIT] PID " << ownerPid << L" (" << ownerName << L") "
                << L"Access: " << AccessMaskToFlags(h.GrantedAccess)
                << (suspicious ? L" [SUSPICIOUS]" : L"")
                << (whitelisted ? L" [WHITELIST]" : L"") << L"\n";
            hits++;
            if (!whitelisted && closeHandles) {
                if (DuplicateHandle(hOwner, (HANDLE)(ULONG_PTR)h.HandleValue, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
                    closed++;
                    std::wcout << L"      -> Closed remote handle\n";
                }
            }
        }

        if (dup) CloseHandle(dup);
        CloseHandle(hOwner);
    }

    std::wcout << L"[+] Done. Hits: " << hits << (closeHandles ? L", Closed: " + std::to_wstring(closed) : L"") << L"\n";
    std::wcout << L"Press Enter to exit...";
    std::wstring dummy;
    std::getline(std::wcin, dummy);
    return 0;
}
