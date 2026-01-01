#pragma once

typedef unsigned long long uintptr_t;

namespace Offsets {
	inline uintptr_t TaskSchedulerPointer = 0x7E1CB88;
	inline uintptr_t TaskSchedulerToJobs = 0x1D0;

	inline uintptr_t NtUnmapViewOfSectionSyscall = 0xD8E428;
}