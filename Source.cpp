#include "Header.h"

#pragma warning(disable : 26451)
#pragma warning(disable : 4100)
#pragma warning(disable : 4189)

EXTERN_C DRIVER_DISPATCH DefaultDispatch;
EXTERN_C DRIVER_UNLOAD DriverUnload;

#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))

unsigned long long _firstAddr = 0;
unsigned long long _secondAddr = 0;
unsigned long long MiFlags = 0x0000000219401268;

auto PageWalker() -> NTSTATUS {

	MM_COPY_ADDRESS _sourceAddress{};
	SIZE_T NumberOfBytesTransferred;
	NTSTATUS status;

	UNICODE_STRING usString{};
	RtlInitUnicodeString(&usString, L"PsInitialSystemProcess");
	auto _address = reinterpret_cast<unsigned long long>(MmGetSystemRoutineAddress(&usString));
	NT_ASSERT(_address != __nullptr);
	DbgPrint("[+] PsInitialSystemProcess: %llX\n", _address);

	unsigned long long physPage;

	auto _largeEnabled = [&](unsigned long long _entry) -> VOID {
		DbgPrint("[+] Large Page enabled\n");

		physPage = ((_entry & 0xFFFFFFFFFF000) + (_address & 0x1fffff));
		
		DbgPrint("[+] Physical Page: %llX\n", physPage);

	};

	auto _cr3 = __readcr3();
	DbgPrint("[+] cr3: %llX\n", _cr3);

	USHORT pml4i = (_address >> 39) & 0x1ff;
	unsigned long long _pml4e = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_cr3) + (pml4i * 8) & 0xfffffffffffffff0);

	status = MmCopyMemory(&_pml4e, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PML4i: %X\t PML4e: %llX\n", pml4i, _pml4e);
	
	USHORT _pdpti = (_address >> 30) & 0x1ff;
	unsigned long long _pdpte = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pml4e & 0xFFFFFFFFFF000) + (_pdpti * 8));
	
	status = MmCopyMemory(&_pdpte, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PDPTi: %X\t PDPTe: %llX\n", _pdpti, _pdpte);

	auto _largePageCheck = (1 << 7) & (_pdpte);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pdpte);
		goto _out;
	}

	USHORT _pdi = (_address >> 21) & 0x1ff;
	unsigned long long _pde = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pdpte & 0xFFFFFFFFFF000) + (_pdi * 8));

	status = MmCopyMemory(&_pde, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PDi: %X\t PDe: %llX\n", _pdi, _pde);

	_largePageCheck = (1 << 7) & (_pde);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pde);
		goto _out;
	}

	USHORT _pti = (_address >> 12) & 0x1ff;
	unsigned long long _pte = 0;
	_sourceAddress.PhysicalAddress.QuadPart = ((_pde & 0xFFFFFFFFFF000) + (_pti * 8));

	status = MmCopyMemory(&_pte, _sourceAddress, sizeof PVOID, MM_COPY_MEMORY_PHYSICAL, &NumberOfBytesTransferred);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[-] MmCopyMemory failed with error code: %X\n", status);
		return status;
	}
	DbgPrint("[+] PTi: %X\t PTe: %llX\n", _pti, _pte);

	_largePageCheck = (1 << 7) & (_pde);
	if (_largePageCheck > 0) {
		// large page bit is set
		_largeEnabled(_pte);
		goto _out;
	}

	USHORT _physIndex = (_address & 0xfff);
	physPage = ((_pte & 0xFFFFFFFFFF000) + _physIndex);
	
	DbgPrint("[+] Physical Page: %llX\n", physPage);

_out:
	auto origPhysical = MmGetPhysicalAddress(reinterpret_cast<PVOID>(_address));
	DbgPrint("[+] Original Physical Address: %llX\n", origPhysical.QuadPart);

	return STATUS_SUCCESS;
}

auto sub_140039AB0(PVOID BaseAddress) -> unsigned long long {
	return NULL;
}

auto __fastcall _MiFillPteHierarchy (unsigned long long address, PTE_HIERARCHY* PteHierarchy) -> VOID {

	auto PatternSearch = [](unsigned long long _start) -> unsigned long long {
		unsigned long long addr = 0;
		unsigned long long templong = 0;
		PUCHAR StartSearchAddress = reinterpret_cast<PUCHAR>(_start);

		for (PUCHAR i = StartSearchAddress; /*i < EndSearchAddress*/; i++) {
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2)) {
				auto b1 = *(i);
				auto b2 = *(i + 1);
				auto b3 = *(i + 2);
				if (b1 == 0xc9 && b2 == 0x49 && b3 == 0xb8) {    // search for MiFillPteHierarchy
					memcpy(&templong, i + 3, 4);
					addr = (ULONGLONG)templong + (ULONGLONG)i + 3; //7
					break;
				}
			}
		}

		return addr;
	};

	auto _ntoskrnl = (unsigned long long) NtosKrnl();
	auto _patternAddr = PatternSearch(_ntoskrnl);
	auto _MiFillVal = *(ULONG64*)_patternAddr;


	auto _pte = reinterpret_cast<PPTE>((((uintptr_t)address >> 9) & 0x7FFFFFFFF8) + _MiFillVal);
	PteHierarchy->PageTableEntry = _pte;

	auto _pde = reinterpret_cast<PPDE>((((uintptr_t)_pte >> 9) & 0x7FFFFFFFF8) + _MiFillVal);
	PteHierarchy->PageDirectoryEntry = _pde;

	auto _pdpte = reinterpret_cast<PPDPTE>((((uintptr_t)_pde >> 9) & 0x7FFFFFFFF8) + _MiFillVal);
	PteHierarchy->PageDirectoryPointerTableEntry = _pdpte;

	auto _pml4e = reinterpret_cast<PPML4E>((((uintptr_t)_pdpte >> 9) & 0x7FFFFFFFF8) + _MiFillVal);
	PteHierarchy->PageMapLevel4Entry = _pml4e;

	DbgPrint("[+] PML4e is at address %p\n", _pml4e);

	DbgPrint("[+] PDPTe is at address %p\n", _pdpte);

	DbgPrint("[+] PDe is at address %p\n", _pde);

	DbgPrint("[+] PTe is at address %p\n", _pte);
};

auto __fastcall _MI_READ_PTE_LOCK_FREE(unsigned __int64 a1) -> unsigned long long {
	__int64 result; // rax
	__int64 v2; // rdx
	__int64 v3; // r8
	__int64 v4; // rcx

	auto _ntoskrnl = (unsigned long long) NtosKrnl();
	auto firstSearch = [](unsigned long long _start) -> unsigned long long {
		unsigned long long addr = 0;
		unsigned long long templong = 0;
		PUCHAR StartSearchAddress = reinterpret_cast<PUCHAR>(_start);

		for (PUCHAR i = StartSearchAddress; /*i < EndSearchAddress*/; i++) {
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2)) {
				auto b1 = *(i);
				auto b2 = *(i + 1);
				auto b3 = *(i + 2);
				if (b1 == 0x01 && b2 == 0x48 && b3 == 0xba) {
					memcpy(&templong, i + 3, 4);
					addr = (ULONGLONG)templong + (ULONGLONG)i + 3; //7
					break;
				}
			}
		}

		return addr;
	};
	auto secondSearch = [](unsigned long long _start) -> unsigned long long {
		unsigned long long addr = 0;
		unsigned long long templong = 0;
		PUCHAR StartSearchAddress = reinterpret_cast<PUCHAR>(_start);

		for (PUCHAR i = StartSearchAddress; /*i < EndSearchAddress*/; i++) {
			if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2)) {
				auto b1 = *(i);
				auto b2 = *(i + 1);
				auto b3 = *(i + 2);
				if (b1 == 0x01 && b2 == 0x48 && b3 == 0xba) {
					memcpy(&templong, i + 3, 4);
					addr = (ULONGLONG)templong + (ULONGLONG)i + 3; //7
					break;
				}
			}
		}

		return addr;
	};
	

	if (!_firstAddr) {
		auto _firstSearch = firstSearch(_ntoskrnl);
		_firstAddr = *(unsigned long long*)_firstSearch;
	}

	if (!_secondAddr) {
		auto _secondSearch = secondSearch(_ntoskrnl);
		_secondAddr = *(unsigned long long*)_secondSearch;
	}

	if (!MiFlags) {

	}
	

	result = *(__int64*)a1;
	if (a1 >= _firstAddr // read this address (subject to ASLR)
		&& a1 <= _secondAddr // read this address (subject to ASLR)
		&& ((MiFlags & 0xC00000) != 0) // will add later on
		&& *(BYTE*)(*(__int64*)(__readgsqword(0x188u) + 0xB8) + 0x288) != 1
		// && *(_BYTE *)(*(_QWORD *)(KeGetCurrentThread()->ApcState->Process)->AddressPolicy) != 1
		&& ((result & 1) != 0)
		&& ((result & 0x20) == 0 || (result & 0x42) == 0))
	{
		v2 = *(__int64*)(*(__int64*)(__readgsqword(0x188u) + 0xB8) + 0x608);
		// KeGetCurrentThread()->Process->Vm->Shared->ShadowMapping;
		if (v2)
		{
			v3 = result | 0x20;
			v4 = *(__int64*)(v2 + 8 * ((a1 >> 3) & 0x1FF));
			if ((v4 & 0x20) == 0)
				v3 = result;
			result = v3;
			if ((v4 & 0x42) != 0)
				return v3 | 0x42;
		}
	}
	return result;
}

auto __fastcall _MiVaToPfn(unsigned long long BaseAddress) -> unsigned long long {
	ULONG index;
	unsigned long long arg_8;
	PTE_HIERARCHY PteHierarchy{};
	RtlZeroMemory(&PteHierarchy, sizeof(PTE_HIERARCHY));

	_MiFillPteHierarchy(BaseAddress, &PteHierarchy);
	PVOID _array[0x4] = { PteHierarchy.PageTableEntry, PteHierarchy.PageDirectoryEntry,
				PteHierarchy.PageDirectoryPointerTableEntry, PteHierarchy.PageMapLevel4Entry };
	index = 4;

	do {
		arg_8 = _MI_READ_PTE_LOCK_FREE((unsigned long long)_array[index - 1]); // get address of page table entry
		--index;

		if ((arg_8 & 0x80u) > 0i64) { // large page present
			break;
		}
		
	} while (index > 0); // pml4e, then pdpte, then pde, then pte

	auto _addr = _MI_READ_PTE_LOCK_FREE((unsigned long long)_array[index]); // arg_8
	DbgPrint("[+] Large Page Present ???? %d read : %llX\n", index, _addr);
	
	_addr = _addr >> 0xC;
	_addr = _addr & 0xFFFFFFFFF;

	if (index > 0) {
		ULONG64 ecx = 1;
		BaseAddress = BaseAddress >> 0xC; // move to pte

		auto _rax = BaseAddress;

		do {
			BaseAddress = BaseAddress >> 0x9;
			_rax &= 0x1FF;
			_rax *= ecx;
			ecx = ecx << 0x9;
			_addr += _rax;
			--index;
		} while (index != 0x0);
	}

	return _addr;
}

auto __fastcall _MI_IS_PHYSICAL_ADDRESS(PVOID BaseAddress) -> BOOLEAN {
	PTE_HIERARCHY PteHierarchy{};
	memset(&PteHierarchy, 0, sizeof(PteHierarchy));

	ULONG index = 4;
	_MiFillPteHierarchy((unsigned long long)BaseAddress, &PteHierarchy);
	PVOID _array[0x4] = { PteHierarchy.PageTableEntry, PteHierarchy.PageDirectoryEntry,
				PteHierarchy.PageDirectoryPointerTableEntry, PteHierarchy.PageMapLevel4Entry };

	do {
		auto _v4 = _array[index - 1];
		auto _v5 = *(PVOID*)_v4;

		--index;

		if ((unsigned long long)_v4 < 0xFFFFF6FB7DBED000) {
			if (((__int64)_v5 & 0x1) == 0x0) {
				return NULL;
			}

			if ((__int64)_v5 < 0x0) { // _v5 & 0x80 == 0
				break;
			}
		}



	} while (index > 1);

	//return index;
	return false;
}

auto __fastcall _MiGetPhysicalAddress(PVOID BaseAddress, PVOID* a2, BYTE* a3) -> BOOLEAN {
	ULONG index;
	PTE_HIERARCHY PteHierarchy{};
	RtlZeroMemory(&PteHierarchy, 0x20);
	auto _address = (unsigned long long)BaseAddress;
	unsigned long long _retAddress = 0ULL;
	unsigned long long _ret2 = 0;

	*a3 = 0;
	if (!_MI_IS_PHYSICAL_ADDRESS(BaseAddress)) {
		_MiFillPteHierarchy(_address, &PteHierarchy);
		PVOID _array[0x4] = { PteHierarchy.PageTableEntry, PteHierarchy.PageDirectoryEntry,
				PteHierarchy.PageDirectoryPointerTableEntry, PteHierarchy.PageMapLevel4Entry };

		index = 4;
		do {
			_retAddress = _MI_READ_PTE_LOCK_FREE((unsigned long long)_array[index - 1]);
			if ((_retAddress & 1) == 0) {
				return FALSE;
			}
			
			--index;
		} while (index > 0); // pml4e, then pdpte, then pde, then pte

		_retAddress = _MI_READ_PTE_LOCK_FREE((unsigned long long)PteHierarchy.PageTableEntry);
		_ret2 = _retAddress;
		if ((_retAddress & 1) == 0) {
			return FALSE;
		}

		if (sub_140039AB0(BaseAddress) == 0x5) {
			//sub_1402CFB78(PteHierarchy.PageTableEntry);
			_retAddress = _MI_READ_PTE_LOCK_FREE((unsigned long long)PteHierarchy.PageTableEntry);
			_ret2 = _retAddress;
		}

		_retAddress = _MI_READ_PTE_LOCK_FREE(_retAddress);
		_retAddress = (_retAddress >> 0xC) & 0xFFFFFFFFF;
		if ((_ret2 & 0x800) != 0) {
			goto _label1;
		}
	}
	else {
		_retAddress = _MiVaToPfn((unsigned long long)BaseAddress);
_label1:
		*a3 = 1;
	}

	_retAddress = _retAddress << 0xC;
	_address = _address & 0xFFF;

	unsigned long long physAddress;
	physAddress = _retAddress + _address;
	*a2 = (PVOID)physAddress;
	DbgPrint("[%s] addr : %llX\n", __FUNCTION__, physAddress);

	return TRUE;
}

auto __fastcall _MmGetPhysicalAddress(PVOID BaseAddress) -> PHYSICAL_ADDRESS {
	ULONG64 arg_10 = 0;
	BYTE arg_8;

	auto v1 = _MiGetPhysicalAddress(BaseAddress, (PVOID*)&arg_10, &arg_8);
	
	
	PHYSICAL_ADDRESS addr{};
	if (v1) {
		addr.QuadPart = arg_10;
		DbgPrint("[%s] addr : %llX\n", __FUNCTION__, arg_10);
	}
	else {
		addr.QuadPart = arg_10 & 0xffffffffffffffff;
		DbgPrint("[%s] addr : %llX\n", __FUNCTION__, arg_10);
	}

	return addr;
}

extern "C" PVOID MiFillPteHierarchy(PVOID, PPTE_HIERARCHY);

EXTERN_C NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING) {

	PDEVICE_OBJECT _devObj;
	IoCreateDevice(DriverObject, 0, __nullptr, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &_devObj);
	DriverObject->DriverUnload = DriverUnload;

	//PageWalker();
	//__debugbreak();
	auto _address = 0xffffb109ff334080;
	auto _retAddress = _MiVaToPfn(_address);
	_retAddress = _retAddress << 0xC;
	_address = _address & 0xFFF;

	unsigned long long physAddress;
	physAddress = _retAddress + _address;
	DbgPrint("[%s] physAddress : %llX\n", __FUNCTION__, physAddress);

	__debugbreak();

	return STATUS_SUCCESS;
}

EXTERN_C VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	IoDeleteDevice(DriverObject->DeviceObject);
}