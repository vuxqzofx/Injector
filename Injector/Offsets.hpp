#pragma once

typedef unsigned long long uintptr_t;

namespace Offsets {
	inline uintptr_t TaskSchedulerPointer = 0x7E1CB88;
	inline uintptr_t TaskSchedulerToJobs = 0x1D0;

	// dm me if you are actually willing to learn what this offset is for and why i chose this syscall.
	inline uintptr_t NtUnmapViewOfSectionSyscall = 0x72B527;
}