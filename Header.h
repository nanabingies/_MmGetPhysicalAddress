#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include <windef.h>
#include <ntimage.h>

#pragma warning(disable : 4201)

typedef struct _PML4E
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PML4E, * PPML4E;
static_assert(sizeof(PML4E) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDPTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PDPTE, * PPDPTE;
static_assert(sizeof(PDPTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PDE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Ignored1 : 1;
			ULONG64 PageSize : 1;
			ULONG64 Ignored2 : 4;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 11;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PDE, * PPDE;
static_assert(sizeof(PDE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE
{
	union
	{
		struct
		{
			ULONG64 Present : 1;
			ULONG64 ReadWrite : 1;
			ULONG64 UserSupervisor : 1;
			ULONG64 PageWriteThrough : 1;
			ULONG64 PageCacheDisable : 1;
			ULONG64 Accessed : 1;
			ULONG64 Dirty : 1;
			ULONG64 PageAccessType : 1;
			ULONG64 Global : 1;
			ULONG64 Ignored2 : 3;
			ULONG64 PageFrameNumber : 36;
			ULONG64 Reserved : 4;
			ULONG64 Ignored3 : 7;
			ULONG64 ProtectionKey : 4;
			ULONG64 ExecuteDisable : 1;
		};
		ULONG64 Value;
	};
} PTE, * PPTE;
static_assert(sizeof(PTE) == sizeof(PVOID), "Size mismatch, only 64-bit supported.");

typedef struct _PTE_HIERARCHY
{
	PPTE PageTableEntry;
	PPDE PageDirectoryEntry;
	PPDPTE PageDirectoryPointerTableEntry;
	PPML4E PageMapLevel4Entry;
}PTE_HIERARCHY, * PPTE_HIERARCHY;

EXTERN_C NTSTATUS ZwQuerySystemInformation(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG* ReturnLength);

typedef struct SYSTEM_MODULE {
	ULONG                Reserved1;
	ULONG                Reserved2;
#ifdef _WIN64
	ULONG				Reserved3;
#endif
	PVOID                ImageBaseAddress;
	ULONG                ImageSize;
	ULONG                Flags;
	WORD                 Id;
	WORD                 Rank;
	WORD                 w018;
	WORD                 NameOffset;
	CHAR                 Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
	ULONG                ModulesCount;
	SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

PVOID NtosKrnl() {

	ULONG size = 0;
	ZwQuerySystemInformation(0xB, NULL, 0, &size);

	PVOID buffer = ExAllocatePool(NonPagedPool, size * sizeof(PVOID));
	ZwQuerySystemInformation(0xB, buffer, size, &size);

	PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
	PVOID addr = moduleInfo->Modules[0].ImageBaseAddress;
	ExFreePool(buffer);
	return addr;
}

__declspec(dllexport)
__declspec(noinline)
void*
GetNtoskrnlBaseAddress()
{
	//
	// From Windows Internals part 1, chapter 2:
	//
	//   "The kernel uses a data structure called the processor control region, or KPCR, to store
	//   processor-specific data. The KPCR contains basic information such as the processor's interrupt
	//   dispatch table(IDT), task - state segment(TSS), and global descriptor table(GDT). It also includes the
	//   interrupt controller state, which it shares with other modules, such as the ACPI driver and the HAL. To
	//   provide easy access to the KPCR, the kernel stores a pointer to it in the fs register on 32-bit Windows
	//   and in the gs register on an x64 Windows system."
	//
	//
	//  Let's view the address of KPCR of the current processor:
	//
	//     1: kd> dg gs
	//       P Si Gr Pr Lo
	//       Sel        Base              Limit          Type    l ze an es ng Flags
	//       ---- ---------------- - ---------------- - ---------- - -- -- -- -- --------
	//       002B ffffd001`1972e000 00000000`ffffffff Data RW Ac 3 Bg Pg P  Nl 00000cf3
	//
	// We only care about one field in KPCR which is IdtBase (it has been always at the offset 0x38):
	//
	//     1: kd> dt nt!_KPCR 0xffffd001`1972e000
	//       + 0x000 NtTib            : _NT_TIB
	//       + 0x000 GdtBase : 0xffffd001`1973b8c0 _KGDTENTRY64
	//       + 0x008 TssBase          : 0xffffd001`19734b40 _KTSS64
	//       + 0x010 UserRsp          : 0x000000c0`87cffc18
	//       + 0x018 Self             : 0xffffd001`1972e000 _KPCR
	//       + 0x020 CurrentPrcb      : 0xffffd001`1972e180 _KPRCB
	//       + 0x028 LockArray        : 0xffffd001`1972e7f0 _KSPIN_LOCK_QUEUE
	//       + 0x030 Used_Self        : 0x000000c0`86875000 Void
	//       + 0x038 IdtBase          : 0xffffd001`1973b930 _KIDTENTRY64      <- pointer to the IDT array
	//       ...
	//
	// The field is a pointer to an array of interrupt service routines in the following format:
	//
	//     1: kd> dt nt!_KIDTENTRY64
	//       +0x000 OffsetLow        : Uint2B
	//       +0x002 Selector         : Uint2B
	//       +0x004 IstIndex         : Pos 0, 3 Bits   --+
	//       +0x004 Reserved0        : Pos 3, 5 Bits     |
	//       +0x004 Type             : Pos 8, 5 Bits     |
	//       +0x004 Dpl              : Pos 13, 2 Bits    |-> the interrupt service routine as a bitfield
	//       +0x004 Present          : Pos 15, 1 Bit     |
	//       +0x006 OffsetMiddle     : Uint2B            |
	//       +0x008 OffsetHigh       : Uint4B          --+
	//       +0x00c Reserved1        : Uint4B
	//       +0x000 Alignment        : Uint8B
	//
	//
	// These interrupt service routines are functions defined within the address space of ntoskrnl.exe. We will
	// use this fact for searching for the base address of ntoskrnl.exe.
	//

	// Ensure that the structure is aligned on 1 byte boundary.
#pragma pack(push, 1)
	typedef struct
	{
		UCHAR Padding[4];
		PVOID InterruptServiceRoutine;
	} IDT_ENTRY;
#pragma pack(pop)

	// Find the address of IdtBase using gs register.
	const auto idt_base = reinterpret_cast<IDT_ENTRY*>(__readgsqword(0x38));

	// Find the address of the first (or any) interrupt service routine.
	const auto first_isr_address = idt_base[0].InterruptServiceRoutine;

	// Align the address on page boundary.
	auto page_within_ntoskrnl = reinterpret_cast<uintptr_t>(first_isr_address) & ~static_cast<uintptr_t>(0xfff);

	// Traverse pages backward until we find the PE signature (MZ) of ntoskrnl.exe in the beginning of some page.
	while (*reinterpret_cast<const USHORT*>(page_within_ntoskrnl) != 0x5a4d)
	{
		page_within_ntoskrnl -= 0x1000;
	}

	// Now we have the base address of ntoskrnl.exe
	return reinterpret_cast<void*>(page_within_ntoskrnl);
}

uintptr_t Getntoskrnlbase() {
	typedef unsigned char uint8_t;
	uintptr_t Idt_base = (uintptr_t)KeGetPcr()->IdtBase;
	uintptr_t align_page = *(uintptr_t*)(Idt_base + 4) >> 0xc << 0xc;

	for (; align_page; align_page -= PAGE_SIZE)
	{
		for (int index = 0; index < PAGE_SIZE - 0x7; index++)
		{
			uintptr_t current_address = (intptr_t)(align_page)+index;

			if (*(uint8_t*)(current_address) == 0x48
				&& *(uint8_t*)(current_address + 1) == 0x8D
				&& *(uint8_t*)(current_address + 2) == 0x1D
				&& *(uint8_t*)(current_address + 6) == 0xFF) //48 8d 1D ?? ?? ?? FF
			{
				uintptr_t nto_base_offset = *(int*)(current_address + 3);
				uintptr_t nto_base_ = (current_address + nto_base_offset + 7);
				if (!(nto_base_ & 0xfff)) {
					return nto_base_;
				}
			}
		}
	}

	return 0x0;
}

PIMAGE_NT_HEADERS getHeader(PVOID module) {
	return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
}

PBYTE FindPattern(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {
	auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL {
		for (auto x = buffer; *mask; pattern++, mask++, x++) {
			auto addr = *(BYTE*)(pattern);
			if (addr != *x && *mask != '?')
				return FALSE;
		}

		return TRUE;
	};

	for (auto x = 0; x < size - strlen(mask); x++) {

		auto addr = (PBYTE)module + x;
		if (checkMask(addr, pattern, mask))
			return addr;
	}

	return NULL;
}

PBYTE FindPattern(PVOID base, LPCSTR pattern, LPCSTR mask) {

	auto header = getHeader(base);
	auto section = IMAGE_FIRST_SECTION(header);

	for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {

		/*
		* Avoids non paged memory,
		* As well as greatly speeds up the process of scanning 30+ sections.
		*/
		if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4)) {
			auto addr = FindPattern((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (addr) {
				DbgPrint("[mapper] Found pattern in Section -> [ %s ]\n", section->Name);
				return addr;
			}
		}
	}

	return NULL;
}