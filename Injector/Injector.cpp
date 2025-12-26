// made by Bytecode (@goodbytecode)

#include <iostream>
#include <vector>

#include "Memory/Memory.hpp"
#include "Mapper/Mapper.hpp"
#include "Defs.hpp"
#include "Offsets.hpp"

uintptr_t HeartbeatHook(uintptr_t a1, uintptr_t a2, uintptr_t a3) {
    auto shared = (Shared*)0x100000000;
    auto OriginalHeartBeat = (THeartBeat)shared->OriginalHeartBeat;

    if (shared->Status == Status::RegisterIC) {
        shared->Status = Status::Wait;

        auto fNtSetInformationProcess = (TNtSetInformationProcess)shared->fNtSetInformationProcess;

        PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION nirvana = {};

        nirvana.Callback = (PVOID)shared->IC;
        nirvana.Reserved = 0;
        nirvana.Version = 0;

        fNtSetInformationProcess((HANDLE)-1, (PROCESS_INFORMATION_CLASS)ProcessInstrumentationCallback, &nirvana, sizeof(nirvana));

        auto fLoadLibraryExA = (TLoadLibraryExA)shared->fLoadLibraryExA;
        fLoadLibraryExA((LPCSTR)shared->StringMSHTML, NULL, DONT_RESOLVE_DLL_REFERENCES);
    }

    if (shared->Status == Status::InjectDLL) {
        uintptr_t dllStart = shared->dllStart;
        uintptr_t exVA = shared->ExceptionVA;
        uintptr_t exSize = shared->ExceptionSize;

        auto pRtlAddFunctionTable = (TRtlAddFunctionTable)shared->fRtlAddFunctionTable;
        auto pLoadLibraryA = (TLoadLibraryA)shared->fLoadLibraryA;
        auto pGetProcAddress = (TGetProcAddress)shared->fGetProcAddress;

        // SEH
        if (exVA && exSize) {
            RUNTIME_FUNCTION* table = (RUNTIME_FUNCTION*)(dllStart + exVA);
            DWORD count = (DWORD)(exSize / sizeof(RUNTIME_FUNCTION));
            pRtlAddFunctionTable(table, count, (DWORD64)dllStart);
        }

        // Imports
        PIMAGE_IMPORT_DESCRIPTOR importStart = (PIMAGE_IMPORT_DESCRIPTOR)(dllStart + shared->ImportVA);
        PIMAGE_IMPORT_DESCRIPTOR importEnd = (PIMAGE_IMPORT_DESCRIPTOR)((uint8_t*)importStart + shared->ImportSize);

        while (importStart < importEnd && importStart->Name) {
            HMODULE loadedDLL = pLoadLibraryA((char*)(dllStart + importStart->Name));
            if (!loadedDLL)
                continue;

            uintptr_t* thunk;
            if (!importStart->OriginalFirstThunk)
                thunk = (uintptr_t*)(dllStart + importStart->FirstThunk);
            else
                thunk = (uintptr_t*)(dllStart + importStart->OriginalFirstThunk);

            FARPROC* func = (FARPROC*)(dllStart + importStart->FirstThunk);

            for (; *thunk; ++thunk, ++func) {
                if (IMAGE_SNAP_BY_ORDINAL(*thunk))
                    *func = pGetProcAddress(loadedDLL, MAKEINTRESOURCEA(IMAGE_ORDINAL(*thunk)));
                else {
                    IMAGE_IMPORT_BY_NAME* importByName = (IMAGE_IMPORT_BY_NAME*)(dllStart + *thunk);
                    *func = pGetProcAddress(loadedDLL, importByName->Name);
                }
            }

            ++importStart;
        }

        // TLS
        if (shared->TLSVA != 0 && shared->TLSSize != 0) {
            uintptr_t dllStart = shared->dllStart;

            IMAGE_TLS_DIRECTORY64* tlsDir = (IMAGE_TLS_DIRECTORY64*)(dllStart + shared->TLSVA);

            ULONGLONG rawCallbacks = tlsDir->AddressOfCallBacks;
            if (rawCallbacks != 0) {
                uintptr_t callbacksVA = (uintptr_t)rawCallbacks;
                if (callbacksVA < dllStart || callbacksVA >= shared->dllEnd)
                    callbacksVA = dllStart + (uintptr_t)rawCallbacks;

                PIMAGE_TLS_CALLBACK* cbList = (PIMAGE_TLS_CALLBACK*)callbacksVA;

                for (size_t i = 0;; ++i) {
                    PIMAGE_TLS_CALLBACK callback = cbList[i];
                    if (callback == nullptr)
                        break;

                    callback((PVOID)dllStart, DLL_PROCESS_ATTACH, nullptr);
                }
            }
        }

        // Call DllMain
        auto dllMain = (BOOL(__stdcall*)(HMODULE, DWORD, LPVOID))(shared->dllEntryPoint);

        dllMain((HMODULE)shared->dllStart, DLL_PROCESS_ATTACH, 0);

        shared->Status = Status::InjectedDLL;
    }

    return OriginalHeartBeat(a1, a2, a3);
}

void __stdcall InstrumentationCallback(PCONTEXT ctx) {
    auto shared = (Shared*)0x100000000;
    uint64_t currentTeb = (uint64_t)NtCurrentTeb();
    ctx->Rip = *(uint64_t*)(currentTeb + 0x02d8);
    ctx->Rsp = *(uint64_t*)(currentTeb + 0x02e0);

    if (ctx->Rip == (shared->HyperionBase + Offsets::NtUnmapViewOfSectionSyscall))
        ctx->Rbx = 0; // i really wanna kill myself

    ctx->Rcx = ctx->R10;
    ctx->R10 = 0;

    auto fRtlRestoreContext = (TRtlRestoreContext)shared->fRtlRestoreContext;
    fRtlRestoreContext(ctx, nullptr);
}

int main() {
    auto exploitDLL = (std::filesystem::current_path() / "exploit.dll").string();
    if (!std::filesystem::exists(exploitDLL)) {
        std::cout << "invalid DLL path\n";
        getchar();
        exit(0);
    }

    DWORD pid = GetPID("RobloxPlayerBeta.exe");
    if (!pid) {
        std::cout << "Failed to get the PID of Roblox.\n";
        getchar();
        exit(0);
    }

    pHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
    if (!pHandle) {
        std::cout << "Failed to open a Handle to Roblox.\n";
        getchar();
        exit(0);
    }

    uintptr_t devenumBase = (uintptr_t)GetModuleEntry(pid, "devenum.dll").modBaseAddr;
    Protect(devenumBase, 0x1000, PAGE_EXECUTE_READWRITE);

    std::vector<BYTE> zeros(0x1000, 0);
    Write(devenumBase, zeros.data(), zeros.size());

    uintptr_t robloxBase = (uintptr_t)GetModuleEntry(pid, "RobloxPlayerBeta.exe").modBaseAddr;
    uintptr_t hyperionBase = (uintptr_t)GetModuleEntry(pid, "RobloxPlayerBeta.dll").modBaseAddr;
    uintptr_t kernelBase = (uintptr_t)GetModuleEntry(pid, "KERNELBASE.dll").modBaseAddr;
    uintptr_t kernel32 = (uintptr_t)GetModuleEntry(pid, "KERNEL32.dll").modBaseAddr;
    uintptr_t ntDLL = (uintptr_t)GetModuleEntry(pid, "ntdll.dll").modBaseAddr;

    uintptr_t fRtlCaptureContext = GetModuleProc(ntDLL, "RtlCaptureContext");

    uintptr_t jobs = Read<uintptr_t>(Read<uintptr_t>(robloxBase + Offsets::TaskSchedulerPointer) + Offsets::TaskSchedulerToJobs);
    uintptr_t heartBeatJob = GetHeartBeat(jobs);
    uintptr_t originalVTable = Read<uintptr_t>(heartBeatJob);
    uintptr_t originalHeartBeat = Read<uintptr_t>(originalVTable + 0x8);

    uintptr_t newVTable = (uintptr_t)VirtualAllocEx(pHandle, 0, 0x300, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    for (uintptr_t i = 0x0; i < 0x300; i += 0x8)
        Write<uintptr_t>(newVTable + i, Read<uintptr_t>(originalVTable + i));

    Write<uintptr_t>(newVTable + 0x8, devenumBase);

    sharedMemory = (uintptr_t)VirtualAllocEx(pHandle, 0, sizeof(Shared), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    std::vector<BYTE> shellcode = ExtractShellcode((uintptr_t)HeartbeatHook);
    std::vector<BYTE> icShellcode = ExtractShellcode((uintptr_t)InstrumentationCallback);
    ReplaceShellcode(shellcode, 0x100000000, sharedMemory);
    ReplaceShellcode(icShellcode, 0x100000000, sharedMemory);

    Write(devenumBase, shellcode.data(), shellcode.size());

    std::cout << "HeartBeat = 0x" << std::hex << heartBeatJob << "\n";

    uintptr_t mshtmlStringBase = (uintptr_t)VirtualAllocEx(pHandle, 0, mshtml.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    Write(mshtmlStringBase, mshtml.data(), mshtml.size());

    uintptr_t icWrapperBase = devenumBase + 0x300;

    WriteShared(StringMSHTML, mshtmlStringBase);
    WriteShared(HyperionBase, hyperionBase);
    WriteShared(OriginalHeartBeat, originalHeartBeat);
    WriteShared(fLoadLibraryExA, GetModuleProc(kernelBase, "LoadLibraryExA"));
    WriteShared(fRtlRestoreContext, GetModuleProc(ntDLL, "RtlRestoreContext"));
    WriteShared(fNtSetInformationProcess, GetModuleProc(ntDLL, "NtSetInformationProcess"));
    WriteShared(fLoadLibraryA, GetModuleProc(kernelBase, "LoadLibraryA"));
    WriteShared(fGetProcAddress, GetModuleProc(kernel32, "GetProcAddress"));
    WriteShared(fRtlAddFunctionTable, GetModuleProc(ntDLL, "RtlAddFunctionTable"));
    WriteShared(IC, icWrapperBase);

    uintptr_t icBase = devenumBase + 0x400;

    memcpy(&icWrapper[37], &fRtlCaptureContext, sizeof(fRtlCaptureContext));
    memcpy(&icWrapper[54], &icBase, sizeof(icBase));

    Write(icWrapperBase, icWrapper.data(), icWrapper.size());
    Write(icBase, icShellcode.data(), icShellcode.size());

    Write<uintptr_t>(heartBeatJob, newVTable); // hook it
    std::cout << "HeartBeat Hooked\n";

    MODULEENTRY32 mshtmlEntry = {};
    do {
        mshtmlEntry = GetModuleEntry(pid, "mshtml.dll");
        Sleep(1);
    } while ((uintptr_t)mshtmlEntry.modBaseAddr == 0);

    uintptr_t mshtmlBase = (uintptr_t)mshtmlEntry.modBaseAddr;

    Protect(mshtmlBase, mshtmlEntry.modBaseSize, PAGE_EXECUTE_READWRITE);
    zeros = std::vector<BYTE>(mshtmlEntry.modBaseSize);
    Write(mshtmlBase, zeros.data(), zeros.size());
    
    // now inject

    dllBase = mshtmlBase;
    dllSize = GetDLLSize(exploitDLL);
    WriteShared(dllStart, mshtmlBase);
    WriteShared(dllEnd, mshtmlBase + dllSize);

    Mapper::Map(exploitDLL);
    Mapper::Inject();

    Write<uintptr_t>(heartBeatJob, originalVTable); // unhook it
    getchar();

    return 0;
}