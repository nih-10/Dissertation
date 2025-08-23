#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <iostream>
#include <thread>
#include <chrono>
#include <fstream>
#include <sstream>
#include <set>
#include <wincrypt.h>
#include <softpub.h>
#include <wintrust.h>

#pragma comment(lib, "wintrust.lib")

#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define ThreadQuerySetWin32StartAddress 9

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation,
    // ... other values omitted
} THREADINFOCLASS;

std::set<std::wstring> trustedModules = {
    L"PwnAdventure3-Win32-Shipping.exe",
    L"ntdll.dll",
    L"nvwgf2um.dll",
    L"XAudio2_7.dll",
    L"mswsock.dll",
    L"CRYPT32.dll",
    L"combase.dll",
    L"MSVCR120.dll"

    // ...add any other legitimate DLLs
};

typedef NTSTATUS(WINAPI* pNtQueryInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength);

// Verify digital signature using WinVerifyTrust API
bool VerifyDigitalSignature(LPCWSTR filePath)
{
    LONG status;
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = filePath;
    fileInfo.hFile = NULL;
    fileInfo.pgKnownSubject = NULL;

    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA winTrustData = {};
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileInfo;
    winTrustData.dwStateAction = 0;
    winTrustData.hWVTStateData = NULL;
    winTrustData.dwProvFlags = WTD_SAFER_FLAG;
    winTrustData.dwUIContext = 0;

    status = WinVerifyTrust(NULL, &policyGUID, &winTrustData);

    return (status == ERROR_SUCCESS);
}

void ScanThreads(DWORD pid, std::wofstream& log) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return;

    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll)
        return;
    auto NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(hNtDll, "NtQueryInformationThread");
    if (!NtQueryInformationThread)
        return;

    THREADENTRY32 te32 = { 0 };
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnap, &te32)) {
        CloseHandle(hSnap);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        CloseHandle(hSnap);
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (!EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        CloseHandle(hSnap);
        CloseHandle(hProcess);
        return;
    }

    do {
        if (te32.th32OwnerProcessID != pid)
            continue;

        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
        if (!hThread)
            continue;

        PVOID startAddress = nullptr;
        NTSTATUS status = NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), nullptr);

        CloseHandle(hThread);

        if (!NT_SUCCESS(status) || !startAddress)
            continue;

        uintptr_t addr = (uintptr_t)startAddress;
        std::wstring moduleName = L"(unknown)";
        std::wstring modulePath = L"";
        bool suspicious = true;  // Assume suspicious unless found in a known and trusted module

        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            MODULEINFO modInfo = { 0 };
            if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                uintptr_t start = (uintptr_t)modInfo.lpBaseOfDll;
                uintptr_t end = start + modInfo.SizeOfImage;

                if (addr >= start && addr < end) {
                    wchar_t szModName[MAX_PATH];
                    if (GetModuleBaseNameW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                        moduleName = szModName;
                    }
                    wchar_t szModPath[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], szModPath, MAX_PATH)) {
                        modulePath = szModPath;
                    }
                    suspicious = false; // Thread belongs to a known module
                    break;
                }
            }
        }

        // Confirm the module is in the trusted list
        bool isTrustedModule = (trustedModules.find(moduleName) != trustedModules.end());

        bool signatureValid = false;
        if (!modulePath.empty()) {
            signatureValid = VerifyDigitalSignature(modulePath.c_str());
        }

        // Whitelist the game EXE regardless of signature validity
        if (moduleName == L"PwnAdventure3-Win32-Shipping.exe") {
            suspicious = false;  // trust unconditionally
        }
        // For other trusted modules, trust even if signature invalid
        else if (isTrustedModule && !signatureValid) {
            suspicious = true;
        }
        // Otherwise flag as suspicious if module is not trusted or signature is invalid
        else if (!isTrustedModule || !signatureValid) {
            suspicious = true;
        }
        else {
            suspicious = false;
        }


        std::wstringstream ss;
        ss << L"[Thread] ID: " << te32.th32ThreadID
            << L" | Start Addr: " << startAddress
            << L" | In Module: " << moduleName;

        if (!signatureValid) {
            ss << L" | Signature: INVALID";
        }
        else {
            ss << L" | Signature: VALID";
        }

        if (suspicious) {
            std::wcout << L"\n [!] Suspicious thread detected! Possible cheat." << std::endl;
            ss << L"\n [!] Suspicious thread detected! Possible cheat.";
        }
        std::wstring msg = ss.str();

        std::wcout << msg << std::endl;
        log << msg << std::endl;

    } while (Thread32Next(hSnap, &te32));

    CloseHandle(hSnap);
    CloseHandle(hProcess);
}

// Find PID by exe name
DWORD FindGamePid(const wchar_t* exeName)
{
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(entry);
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (!_wcsicmp(entry.szExeFile, exeName))
            {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return 0;
}

int main()
{
    const wchar_t* gameExe = L"PwnAdventure3-Win32-Shipping.exe";
    std::wofstream log("cheatwatch.log", std::ios::app); // append mode
    if (!log)
    {
        std::wcerr << L"[-] Failed to open log file!" << std::endl;
        return 1;
    }

    log << L"[+] Anti-Cheat: persistent watchdog started." << std::endl;
    std::wcout << L"[+] Anti-Cheat: persistent watchdog started." << std::endl;

    while (true)
    {
        DWORD gamePid = 0;
        while ((gamePid = FindGamePid(gameExe)) == 0)
        {
            std::wcout << L"[*] Waiting for game to start..." << std::endl;
            log << L"[*] Waiting for game to start..." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        std::wcout << L"[+] Game detected! PID: " << gamePid << std::endl;
        log << L"[+] Game detected! PID: " << gamePid << std::endl;

        while (FindGamePid(gameExe) != 0)
        {
            std::wcout << L"SCAN BEGIN" << std::endl;
            log << L"[+] SCAN BEGIN" << std::endl;

            ScanThreads(gamePid, log);

            std::this_thread::sleep_for(std::chrono::seconds(10));
        }
        std::wcout << L"[*] Game closed. Anti-cheat will wait for restart..." << std::endl;
        log << L"[*] Game closed. Anti-cheat will wait for restart..." << std::endl;
    }

    log.flush();
    log.close();
    return 0;
}
