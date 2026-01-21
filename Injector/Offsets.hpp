#pragma once

typedef unsigned long long uintptr_t;

namespace Offsets {
    inline uintptr_t TaskSchedulerPointer = 0x8056DC8;
    inline uintptr_t TaskSchedulerToJobs = 0x1D0;

    inline uintptr_t NtUnmapViewOfSectionSyscall = 0xD962B8;
}
