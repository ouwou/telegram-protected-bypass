#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <iostream>

uint8_t *scan(const char *pattern, const char *mask, uint8_t *begin, uintptr_t size) {
    auto len = std::strlen(mask);

    for (size_t i = 0; i < size; i++) {
        bool f = true;
        for (size_t j = 0; j < len; j++) {
            if (mask[j] != '?' && (uint8_t)pattern[j] != (uint8_t) * (begin + i + j)) {
                f = false;
                break;
            }
        }
        if (f) {
            return (begin + i);
        }
    }
    return nullptr;
}

DWORD WINAPI ThreadRoutine(LPVOID lpThreadParameter) {
    auto hmod = GetModuleHandleA(0);
    auto header = (PIMAGE_DOS_HEADER)hmod;
    auto pe = (PIMAGE_NT_HEADERS)((uint8_t *)header + header->e_lfanew);

    auto sectionHeader = IMAGE_FIRST_SECTION(pe);

    DWORD textSize = 0;
    for (UINT i = 0; i < pe->FileHeader.NumberOfSections; i++, sectionHeader++) {
        if (!std::strcmp((char *)sectionHeader->Name, ".text")) {
            textSize = sectionHeader->Misc.VirtualSize;
        }
    }
    if (textSize == 0) return FALSE;

    auto ptr = scan("\xc1\xe8\x14\xf6\xd0\x24\x01\xc3", "xxxxxxxx", (uint8_t *)hmod, textSize);
    DWORD old;
    VirtualProtect(ptr, 10, PAGE_EXECUTE_READWRITE, &old);
    ptr[5] = 0xB0;
    VirtualProtect(ptr, 10, old, &old);

    return FALSE;
}

BOOL WINAPI DllMain(HMODULE hInstance, DWORD dwReasonForCall, LPVOID lpReserved) {
    if (dwReasonForCall == DLL_PROCESS_ATTACH) {
#ifdef _DEBUG
        AllocConsole();
        AttachConsole(GetCurrentProcessId());
        freopen("CONIN$", "r", stdin);
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
#endif
        CreateThread(0, 0, ThreadRoutine, hInstance, 0, 0);
    }

    return TRUE;
}
