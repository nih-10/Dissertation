#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include <iostream>
#include <string>

DWORD FindProcessId(const std::wstring& processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (processName == entry.szExeFile) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}

bool IsDebuggerAttached(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;

    BOOL isDebugger = FALSE;
    if (CheckRemoteDebuggerPresent(hProc, &isDebugger) && isDebugger) {
        CloseHandle(hProc);
        return true;
    }

    // Optional: NtQueryInformationProcess for deeper check
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (hNtDll) {
        using NtQueryInformationProcess_t =
            NTSTATUS(WINAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);

        auto NtQueryInformationProcess =
            (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");

        if (NtQueryInformationProcess) {
            DWORD debugPort = 0;
            NTSTATUS status = NtQueryInformationProcess(hProc, 7, &debugPort, sizeof(debugPort), nullptr);
            if (status == 0 && debugPort != 0) {
                CloseHandle(hProc);
                return true;
            }
        }
    }

    CloseHandle(hProc);
    return false;
}

int main() {
    std::wstring targetProc = L"PwnAdventure3-Win32-Shipping.exe"; // adjust if different
    DWORD pid = 0;

    while (true) {
        if (pid == 0) {
            pid = FindProcessId(targetProc);
            if (pid == 0) {
                std::wcout << L"[AntiCheat] Waiting for " << targetProc << L"...\n";
                Sleep(2000);
                continue;
            }
            std::wcout << L"[AntiCheat] Found game process (PID " << pid << L")\n";
        }

        if (IsDebuggerAttached(pid)) {
            std::cout << "[!] Debugger detected on PwnAdventure3! Closing game...\n";
            HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
            if (hProc) {
                TerminateProcess(hProc, 0);
                CloseHandle(hProc);
            }
            return 0;
        }

        Sleep(2000); // check every 2s
    }

    return 0;
}
