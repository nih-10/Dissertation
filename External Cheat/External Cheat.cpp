#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <vector>
#include <thread>

const wchar_t* TARGET_PROCESS = L"PwnAdventure3-Win32-Shipping.exe";
const wchar_t* TARGET_MODULE = L"GameLogic.dll";

DWORD GetProcessIdByName(const wchar_t* processName) {
    PROCESSENTRY32 entry = { sizeof(entry) };
    DWORD procId = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (Process32First(snap, &entry)) {
        do {
            if (!_wcsicmp(entry.szExeFile, processName)) {
                procId = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName) {
    MODULEENTRY32 modEntry = { sizeof(modEntry) };
    uintptr_t modBase = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (Module32First(snap, &modEntry)) {
        do {
            if (!_wcsicmp(modEntry.szModule, modName)) {
                modBase = (uintptr_t)modEntry.modBaseAddr;
                break;
            }
        } while (Module32Next(snap, &modEntry));
    }
    CloseHandle(snap);
    return modBase;
}

// Resolve pointer chain: base + offsets
uintptr_t ResolvePointer(HANDLE hProcess, uintptr_t base, const std::vector<unsigned int>& offsets) {
    uintptr_t addr = base;
    for (unsigned int offset : offsets) {
        ReadProcessMemory(hProcess, (LPCVOID)addr, &addr, sizeof(addr), nullptr);
        addr += offset;
    }
    return addr;
}

int main() {
    DWORD procId = GetProcessIdByName(TARGET_PROCESS);
    if (!procId) {
        std::cerr << "[-] Process not found.\n";
        return 1;
    }
    std::cout << "[+] Found process ID: " << procId << "\n";

    HANDLE hProc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, procId);
    if (!hProc) {
        std::cerr << "[-] Failed to open process.\n";
        return 1;
    }

    uintptr_t baseModule = 0;
    while (!(baseModule = GetModuleBaseAddress(procId, TARGET_MODULE))) {
        std::cout << "[*] Waiting for module to load...\n";
        Sleep(100);
    }
    std::cout << "[+] GameLogic.dll base: 0x" << std::hex << baseModule << std::endl;

    // Resolve player base first: base + 0x97D7C
    uintptr_t playerBase = baseModule + 0x97D7C;
    std::vector<unsigned int> offsets = { 0x4, 0x8, 0x10 };
    uintptr_t resolved;
    ReadProcessMemory(hProc, (LPCVOID)playerBase, &resolved, sizeof(resolved), nullptr);

    for (unsigned int off : offsets) {
        ReadProcessMemory(hProc, (LPCVOID)(resolved + off), &resolved, sizeof(resolved), nullptr);
    }

    // Final step: apply -0x40
    uintptr_t healthAddr = resolved - 0x40;
	uintptr_t manaAddr = resolved + 0xBC;

    std::cout << "[+] Health address: 0x" << std::hex << healthAddr << "\n";
    std::cout << "[+] Mana address:   0x" << std::hex << manaAddr << "\n";

    float newHealth = 999.0f;
    float newMana = 999.0f;

    std::cout << "[*] Press F1 to write infinite health & mana.\n";
    std::cout << "[*] Press END to exit.\n";

    while (true) {
        if (GetAsyncKeyState(VK_F1) & 1) {
            WriteProcessMemory(hProc, (LPVOID)healthAddr, &newHealth, sizeof(newHealth), nullptr);
            WriteProcessMemory(hProc, (LPVOID)manaAddr, &newMana, sizeof(newMana), nullptr);
            std::cout << "[+] Overwrote health & mana.\n";
        }

        if (GetAsyncKeyState(VK_END) & 1) {
            std::cout << "[*] Exiting.\n";
            break;
        }

        Sleep(100);
    }

    CloseHandle(hProc);
    return 0;
}
