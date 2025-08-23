#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0)
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

std::wstring GetDllPath(const std::wstring& dllName)
{
    wchar_t buffer[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, buffer);
    std::wstring cwd(buffer);
    return cwd + L"\\" + dllName;
}

bool InjectDll(HANDLE hProcess, const std::wstring& dllPath)
{
    void* allocAddr = VirtualAllocEx(hProcess, nullptr,
        (dllPath.size() + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!allocAddr)
    {
        std::wcerr << L"[!] Failed to allocate memory in target process for " << dllPath << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, allocAddr, dllPath.c_str(),
        (dllPath.size() + 1) * sizeof(wchar_t), nullptr))
    {
        std::wcerr << L"[!] Failed to write DLL path into target process for " << dllPath << std::endl;
        VirtualFreeEx(hProcess, allocAddr, 0, MEM_RELEASE);
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibraryW =
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        pLoadLibraryW, allocAddr, 0, nullptr);
    if (!hThread)
    {
        std::wcerr << L"[!] Failed to create remote thread for " << dllPath << std::endl;
        VirtualFreeEx(hProcess, allocAddr, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, allocAddr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    std::wcout << L"[+] Injected " << dllPath << std::endl;
    return true;
}

int main()
{
    std::wstring processName = L"PwnAdventure3-Win32-Shipping.exe";

    DWORD procId = FindProcessId(processName);
    if (!procId)
    {
        std::wcerr << L"[!] Process not found!" << std::endl;
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
    if (!hProcess)
    {
        std::wcerr << L"[!] Failed to open process!" << std::endl;
        return 1;
    }

    // inject mswsock.dll
    InjectDll(hProcess, GetDllPath(L"mswsock.dll"));

    // inject CheatDLL.dll
    InjectDll(hProcess, GetDllPath(L"CheatDLL.dll"));

    CloseHandle(hProcess);

    std::wcout << L"[+] Injection sequence complete!" << std::endl;
    return 0;
}
