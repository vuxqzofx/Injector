#pragma once

#include <vector>

#include <Windows.h>
#include <TlHelp32.h>

HANDLE pHandle;
DWORD oldP;

template<typename T>
T Read(uintptr_t address) {
    T buffer{};
    ReadProcessMemory(pHandle, (LPCVOID)address, &buffer, sizeof(T), nullptr);

    return buffer;
}

bool Read(uintptr_t address, void* outBuffer, size_t size) {
    return ReadProcessMemory(pHandle, (LPCVOID)address, outBuffer, size, nullptr);
}

template<typename T>
bool Write(uintptr_t address, const T& value) {
    return WriteProcessMemory(pHandle, (LPVOID)address, &value, sizeof(T), nullptr);
}

bool Write(uintptr_t address, const void* buffer, size_t size) {
    return WriteProcessMemory(pHandle, (LPVOID)address, buffer, size, nullptr);
}

bool Protect(uintptr_t address, SIZE_T size, DWORD newProtection) {
    return VirtualProtectEx(pHandle, (LPVOID)address, size, newProtection, &oldP);
}

DWORD GetPID(const char* exeName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32 pe = {};
    pe.dwSize = sizeof(PROCESSENTRY32);

    for (BOOL ok = Process32First(snap, &pe); ok; ok = Process32Next(snap, &pe)) {
        if (!_stricmp(pe.szExeFile, exeName)) {
            CloseHandle(snap);
            return pe.th32ProcessID;
        }
    }

    CloseHandle(snap);
    return 0;
}

MODULEENTRY32 GetModuleEntry(DWORD pid, const char* mod) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE)
        return {};

    MODULEENTRY32 me = {};
    me.dwSize = sizeof(MODULEENTRY32);

    for (BOOL ok = Module32First(snap, &me); ok; ok = Module32Next(snap, &me)) {
        if (!_stricmp(me.szModule, mod)) {
            CloseHandle(snap);
            return me;
        }
    }

    CloseHandle(snap);
    return {};
}

uintptr_t GetModuleProc(uintptr_t moduleBase, const char* functionName) {
    auto dosHeader = Read<IMAGE_DOS_HEADER>(moduleBase);
    auto ntHeaders = Read<IMAGE_NT_HEADERS>(moduleBase + dosHeader.e_lfanew);
    auto exportDirData = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDirData.VirtualAddress == 0 || exportDirData.Size == 0)
        return 0;

    auto exportDir = Read<IMAGE_EXPORT_DIRECTORY>(moduleBase + exportDirData.VirtualAddress);

    std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
    std::vector<WORD> ordinals(exportDir.NumberOfNames);
    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);

    if (!Read(moduleBase + exportDir.AddressOfNames, nameRVAs.data(), sizeof(DWORD) * nameRVAs.size()))
        return 0;

    if (!Read(moduleBase + exportDir.AddressOfNameOrdinals, ordinals.data(), sizeof(WORD) * ordinals.size()))
        return 0;

    if (!Read(moduleBase + exportDir.AddressOfFunctions, functionRVAs.data(), sizeof(DWORD) * functionRVAs.size()))
        return 0;

    char nameBuffer[256];
    for (size_t i = 0; i < nameRVAs.size(); ++i) {
        if (!Read(moduleBase + nameRVAs[i], nameBuffer, sizeof(nameBuffer)))
            continue;

        if (!strcmp(nameBuffer, functionName)) {
            WORD ordinal = ordinals[i];
            if (ordinal >= functionRVAs.size())
                return 0;

            return moduleBase + functionRVAs[ordinal];
        }
    }

    return 0;
}

uintptr_t GetHeartBeat(uintptr_t jobs) {
    for (uintptr_t idx = 0x0; idx < 0x400; idx += 0x10) {
        uintptr_t job = Read<uintptr_t>(jobs + idx);
        if (!job)
            continue;

        int jobNameSize = Read<int>(job + 0x28);
        if (jobNameSize < 16) {
            std::string jobName = Read<std::string>(job + 0x18);
            if (jobName == "Heartbeat")
                return job;
        }
    }

    return 0;
}

std::vector<BYTE> ExtractShellcode(uintptr_t func) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((void*)func, &mbi, sizeof(mbi));

    size_t functionSize = mbi.RegionSize;

    std::vector<BYTE> shellcode;
    for (size_t i = 0; i < functionSize; ++i) {
        BYTE value = *(BYTE*)(func + i);
        shellcode.push_back(value);

        if (value == 0xCC && *(BYTE*)(func + i + 1) == 0xCC && *(BYTE*)(func + i + 2) == 0xCC)
            break;
    }

    return shellcode;
}

void ReplaceShellcode(std::vector<BYTE>& data, uint64_t searchValue, uint64_t replaceValue) {
    const BYTE movBaseOpcode = 0xB8;

    for (size_t i = 0; i <= data.size() - 10; ++i) {
        if ((data[i] == 0x48 || data[i] == 0x49) && data[i + 1] >= movBaseOpcode && data[i + 1] <= movBaseOpcode + 7) {
            uint64_t imm = *(uint64_t*)(&data[i + 2]);
            uint32_t offset = *(uint32_t*)(&data[i + 2]);
            if (imm - offset == searchValue) {
                uintptr_t newValue = replaceValue + offset;
                memcpy(&data[i + 2], &newValue, sizeof(newValue));
            }
        }

        uint64_t immQ = *(uint64_t*)(&data[i + 1]);
        uint32_t immO = *(uint32_t*)(&data[i + 1]);
        if ((data[i] == 0xA1 || data[i] == 0xA2 || data[i] == 0xA3) && immQ - immO == searchValue) {
            uintptr_t newValue = replaceValue + immO;
            memcpy(&data[i + 1], &newValue, sizeof(newValue));
        }
    }
}