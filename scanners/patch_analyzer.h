#pragma once

#include "module_data.h"
#include "patch_list.h"
#include <set>

namespace pesieve {

	//! A postprocessor of the detected code patches. Detects if the patch is a hook, and if so, tries to indentify the address where it leads to.
	class PatchAnalyzer
	{
	public:
		typedef enum {
			OP_SHORTJMP = 0xEB,
			OP_JMP = 0xE9,
			OP_CALL_DWORD = 0xE8,
			OP_PUSH_DWORD = 0x68,
			OP_JMP_VIA_ADDR_B1 = 0xFF,
			OP_JMP_VIA_ADDR_B2 = 0x25
		} t_hook_opcode;

		PatchAnalyzer(ModuleData &_moduleData, DWORD _sectionRVA, PBYTE original_code, PBYTE patched_code, size_t code_size)
			: moduleData(_moduleData), sectionRVA(_sectionRVA),
			originalCode(original_code), patchedCode(patched_code), codeSize(code_size)
		{
			isModule64bit = moduleData.is64bit();
			moduleData.loadRelocatedFields(relocs);
		}

		size_t analyzeHook(PatchList::Patch &patch);

		size_t analyzeOther(PatchList::Patch& patch);

	protected:
		size_t _analyzeHook(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va);
		size_t _analyzeRelocated(PatchList::Patch &patch, BYTE* patch_ptr);

		size_t parseJmpViaAddr(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va);
		size_t parseShortJmp(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va);
		size_t parseJmp(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va);
		size_t parseMovJmp(PatchList::Patch &patch, BYTE* patch_ptr, bool is_long);
		size_t parsePushRet(PatchList::Patch &patch, BYTE* patch_ptr);

		template <typename DELTA_T>
		ULONGLONG getJmpDestAddr(ULONGLONG currVA, int instrLen, DELTA_T lVal) const;

		bool isOriginalRangePadding(DWORD rva, size_t size) const;
		bool isOriginalVaPadding(ULONGLONG va, size_t size) const;
		bool isFunctionEntry(DWORD rva) const;
		bool looksLikeFunctionPrologue(const BYTE* code, size_t size) const;
		bool looksLikeHotpatchPrologue(const BYTE* code, size_t size) const;
		bool startsWithFlowTransfer(const BYTE* code, size_t size) const;
		bool containsJumpBack(const BYTE* code, size_t size, ULONGLONG codeVa, ULONGLONG destination) const;
		bool targetHasCopiedPrologue(const BYTE* targetCode, size_t targetSize, DWORD instructionRva, size_t instructionSize) const;
		bool isClassicHotpatchSlot(DWORD instructionRva, size_t patchSize) const;
		bool isHotpatchEntryJump(DWORD instructionRva, size_t patchSize, ULONGLONG targetVa) const;
		size_t readCurrentBytes(ULONGLONG va, BYTE* buffer, size_t bufferSize) const;
		std::string bytesToHex(const BYTE* data, size_t size) const;
		PatchInjectionContext makePatchContext(PatchList::Patch& patch, DWORD instructionRva, size_t patchSize) const;

		bool is64Modifier(BYTE op);
		bool isLongModifier(BYTE op);

		bool isModule64bit;

		ModuleData &moduleData;
		DWORD sectionRVA;
		PBYTE originalCode;
		PBYTE patchedCode;
		size_t codeSize;

		std::set<DWORD> relocs;
	};

}; //namespace pesieve

