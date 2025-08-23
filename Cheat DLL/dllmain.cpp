#include "pch.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <thread>
#include <vector>

bool speedEnabled = false;
bool jumpEnabled = false;

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry = { 0 };
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
    }
    return modBaseAddr;
}

uintptr_t ResolvePointer(uintptr_t base, std::vector<unsigned int> offsets)
{
    uintptr_t address = base;

    for (unsigned int i = 0; i < offsets.size(); ++i)
    {
        address = *(uintptr_t*)address;
        address += offsets[i];
    }
    return address;
}

void WriteMemory(BYTE* dst, BYTE* src, unsigned int size)
{
    DWORD oldProtect;
    VirtualProtect(dst, size, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(dst, src, size);
    VirtualProtect(dst, size, oldProtect, &oldProtect);
}

void Logic(uintptr_t gameLogicBase)
{
    float hackSpeedVal = 700.0f;
    while (true)
    {
        if (GetAsyncKeyState(VK_F1) & 0x8000)
            speedEnabled = !speedEnabled;
        if (GetAsyncKeyState(VK_F2) & 0x8000)
            jumpEnabled = !jumpEnabled;

        DWORD procId = GetCurrentProcessId();
        uintptr_t playerBase = GetModuleBaseAddress(procId, L"GameLogic.dll");

        if (speedEnabled)
        {
            WriteMemory((BYTE*)ResolvePointer(playerBase + 0x97D7C, { 0x4, 0x8, 0x10, 0x120 }), (BYTE*)&hackSpeedVal, sizeof(hackSpeedVal)); // Walk speed
        }

        if (jumpEnabled)
        {
            WriteMemory((BYTE*)ResolvePointer(playerBase + 0x97D7C, { 0x4, 0x8, 0x10, 0x124 }), (BYTE*)&hackSpeedVal, sizeof(hackSpeedVal)); // Jump speed
        }

        if (GetAsyncKeyState(VK_END) & 1)
        {
            break; // Exit loop on END
        }

        Sleep(50); // Avoid high CPU usage
    }
}

DWORD WINAPI PwnIsland(LPVOID lpParam)
{
    DWORD procId = GetCurrentProcessId();
    uintptr_t baseAddr = GetModuleBaseAddress(procId, L"GameLogic.dll");
    Logic(baseAddr);
    FreeLibraryAndExitThread((HMODULE)lpParam, 0);
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, PwnIsland, hModule, 0, nullptr);
    }
    return TRUE;
}
