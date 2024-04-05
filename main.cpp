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

    // patch PeerData::allowsForwarding
    auto ptr = scan("\x48\x85\xC0\x74\x00\xB0\x00\xC3\x41", "xxxx?x?xx", (uint8_t *)hmod, textSize);
    DWORD old;
    VirtualProtect(ptr, 10, PAGE_EXECUTE_READWRITE, &old);
    ptr[3] = 0x90;
    ptr[4] = 0x90;
    VirtualProtect(ptr, 10, old, &old);

    // patch HistoryInner::showCopyRestrictionForSelected
    ptr = scan("\x80\x7B\x00\x00\x75\x00\x0F\x1F\x00\x48\x8B\x53", "xx??x?xxxxxx", (uint8_t*)hmod, textSize);
    VirtualProtect(ptr, 10, PAGE_EXECUTE_READWRITE, &old);
    ptr[4] = 0xEB;
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
