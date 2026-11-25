#include "patch_analyzer.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
//---
using namespace pesieve;

template <typename DELTA_T>
ULONGLONG pesieve::PatchAnalyzer::getJmpDestAddr(ULONGLONG currVA, int instrLen, DELTA_T lVal) const
{
	int delta = instrLen + int(lVal);
	ULONGLONG addr = currVA + delta;
	return addr;
}

namespace {

	bool is_padding_byte(BYTE value)
	{
		return value == 0x00 || value == 0x90 || value == 0xCC;
	}

	bool is_padding_buffer(const BYTE* data, size_t size)
	{
		if (!data || !size) {
			return false;
		}
		const BYTE first = data[0];
		if (!is_padding_byte(first)) {
			return false;
		}
		for (size_t i = 1; i < size; i++) {
			if (data[i] != first) {
				return false;
			}
		}
		return true;
	}

}; //namespace

bool pesieve::PatchAnalyzer::isOriginalRangePadding(DWORD rva, size_t size) const
{
	if (!moduleData.original_module || !moduleData.original_size || !size) {
		return false;
	}
	if (rva >= moduleData.original_size || size > (moduleData.original_size - rva)) {
		return false;
	}
	return is_padding_buffer(moduleData.original_module + rva, size);
}

bool pesieve::PatchAnalyzer::isOriginalVaPadding(ULONGLONG va, size_t size) const
{
	const ULONGLONG module_base = (ULONGLONG)moduleData.moduleHandle;
	if (va < module_base) {
		return false;
	}
	const ULONGLONG offset = va - module_base;
	if (offset >= moduleData.original_size) {
		return false;
	}
	return isOriginalRangePadding((DWORD)offset, size);
}

bool pesieve::PatchAnalyzer::looksLikeHotpatchPrologue(const BYTE* code, size_t size) const
{
	if (!code || size < 2) {
		return false;
	}
	// mov edi, edi (the five-byte hotpatch reservation follows it)
	if (code[0] == 0x8B && code[1] == 0xFF) {
		return true;
	}
	// Some x64 builds reserve the slot with NOPs.
	if (code[0] == 0x90 && code[1] == 0x90) {
		return true;
	}
	return false;
}

bool pesieve::PatchAnalyzer::looksLikeFunctionPrologue(const BYTE* code, size_t size) const
{
	if (!code || size < 2) {
		return false;
	}
	if (looksLikeHotpatchPrologue(code, size)) {
		return true;
	}
	// push ebp; mov ebp, esp
	if (code[0] == 0x55 && size >= 3 && code[1] == 0x8B && (code[2] == 0xEC || code[2] == 0xE5)) {
		return true;
	}
	// x64 common prologues
	if (code[0] == 0x48 && size >= 3) {
		switch (code[1]) {
		case 0x89:
		case 0x8B:
		case 0x83:
		case 0x81:
		case 0x8D:
			return true;
		default:
			break;
		}
	}
	// push rbx/rbp/rsi/rdi or REX + push
	if ((code[0] == 0x53 || code[0] == 0x55 || code[0] == 0x56 || code[0] == 0x57)
		&& (code[1] == 0x8B || code[1] == 0x48 || code[1] == 0x53 || code[1] == 0x55 || code[1] == 0x56 || code[1] == 0x57)) {
		return true;
	}
	if (code[0] == 0x40 && size >= 2
		&& (code[1] == 0x53 || code[1] == 0x55 || code[1] == 0x56 || code[1] == 0x57 || code[1] == 0x48)) {
		return true;
	}
	// 32-bit stack adjustment or argument loading prologues
	if (code[0] == 0x83 && size >= 2 && (code[1] == 0xEC || code[1] == 0xE4)) {
		return true;
	}
	if (code[0] == 0x8B && size >= 2 && (code[1] == 0x44 || code[1] == 0x4C || code[1] == 0x54 || code[1] == 0x5C)) {
		return true;
	}
	if (code[0] == 0x6A || code[0] == 0x68) {
		return true;
	}
	return false;
}

bool pesieve::PatchAnalyzer::isFunctionEntry(DWORD rva) const
{
	if (!moduleData.original_module || rva >= moduleData.original_size) {
		return false;
	}
	const DWORD ep = peconv::get_entry_point_rva(moduleData.original_module);
	if (ep == rva) {
		return true;
	}
	const size_t remaining = moduleData.original_size - rva;
	return looksLikeFunctionPrologue(moduleData.original_module + rva, remaining);
}

bool pesieve::PatchAnalyzer::startsWithFlowTransfer(const BYTE* code, size_t size) const
{
	if (!code || size < 2) {
		return false;
	}
	if (code[0] == OP_JMP || code[0] == OP_SHORTJMP || code[0] == OP_CALL_DWORD) {
		return true;
	}
	if (code[0] == OP_JMP_VIA_ADDR_B1 && code[1] == OP_JMP_VIA_ADDR_B2) {
		return true;
	}
	return false;
}

bool pesieve::PatchAnalyzer::containsJumpBack(const BYTE* code, size_t size, ULONGLONG codeVa, ULONGLONG destination) const
{
	if (!code || size < 2) {
		return false;
	}
	const size_t max_scan = size < 32 ? size : 32;
	for (size_t i = 0; i + 2 <= max_scan; i++) {
		const ULONGLONG currVa = codeVa + i;
		if (code[i] == OP_SHORTJMP) {
			const int8_t delta = (int8_t)code[i + 1];
			if (getJmpDestAddr<int8_t>(currVa, 2, delta) == destination) {
				return true;
			}
		}
		if (code[i] == OP_JMP && i + 5 <= max_scan) {
			int32_t delta = 0;
			memcpy(&delta, code + i + 1, sizeof(delta));
			if (getJmpDestAddr<int32_t>(currVa, 5, delta) == destination) {
				return true;
			}
		}
	}
	return false;
}

bool pesieve::PatchAnalyzer::targetHasCopiedPrologue(const BYTE* targetCode, size_t targetSize, DWORD instructionRva, size_t instructionSize) const
{
	if (!targetCode || !moduleData.original_module || !instructionSize) {
		return false;
	}
	if (instructionRva >= moduleData.original_size) {
		return false;
	}
	const size_t originalSize = moduleData.original_size - instructionRva;
	size_t compareSize = instructionSize < 8 ? instructionSize : 8;
	if (compareSize > originalSize) compareSize = originalSize;
	if (compareSize > targetSize) compareSize = targetSize;
	if (compareSize < 2) {
		return false;
	}
	return memcmp(targetCode, moduleData.original_module + instructionRva, compareSize) == 0;
}

size_t pesieve::PatchAnalyzer::readCurrentBytes(ULONGLONG va, BYTE* buffer, size_t bufferSize) const
{
	if (!buffer || !bufferSize || !va) {
		return 0;
	}
	const ULONGLONG sectionVa = moduleData.rvaToVa(sectionRVA);
	if (va >= sectionVa && (va + bufferSize) <= (sectionVa + codeSize)) {
		memcpy(buffer, patchedCode + (va - sectionVa), bufferSize);
		return bufferSize;
	}
	if (!moduleData.processHandle) {
		return 0;
	}
	return peconv::read_remote_memory(moduleData.processHandle, (LPVOID)va, buffer, bufferSize);
}

std::string pesieve::PatchAnalyzer::bytesToHex(const BYTE* data, size_t size) const
{
	if (!data || !size) {
		return "";
	}
	std::stringstream ss;
	for (size_t i = 0; i < size; i++) {
		if (i) ss << " ";
		ss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)data[i];
	}
	return ss.str();
}

bool pesieve::PatchAnalyzer::isClassicHotpatchSlot(DWORD instructionRva, size_t patchSize) const
{
	if (!patchSize || patchSize > 8) {
		return false;
	}
	if (!isOriginalRangePadding(instructionRva, patchSize)) {
		return false;
	}
	const DWORD entryRva = instructionRva + (DWORD)patchSize;
	if (!moduleData.original_module || entryRva >= moduleData.original_size) {
		return false;
	}
	if (entryRva < sectionRVA) {
		return false;
	}
	const size_t entryOffset = entryRva - sectionRVA;
	if (entryOffset + 2 > codeSize) {
		return false;
	}
	const BYTE* entryCode = patchedCode + entryOffset;
	if (entryCode[0] != OP_SHORTJMP) {
		return false;
	}
	const ULONGLONG entryVa = moduleData.rvaToVa(entryRva);
	const ULONGLONG jumpTarget = getJmpDestAddr<int8_t>(entryVa, 2, (int8_t)entryCode[1]);
	if (jumpTarget != moduleData.rvaToVa(instructionRva)) {
		return false;
	}
	BYTE slotCode[8] = { 0 };
	const size_t read = readCurrentBytes(moduleData.rvaToVa(instructionRva), slotCode, patchSize);
	if (!read || !startsWithFlowTransfer(slotCode, read)) {
		return false;
	}
	const size_t entryOrigSize = moduleData.original_size - entryRva;
	return looksLikeHotpatchPrologue(moduleData.original_module + entryRva, entryOrigSize);
}

bool pesieve::PatchAnalyzer::isHotpatchEntryJump(DWORD instructionRva, size_t patchSize, ULONGLONG targetVa) const
{
	if (!patchSize || patchSize > 5) {
		return false;
	}
	const ULONGLONG sourceVa = moduleData.rvaToVa(instructionRva);
	if (targetVa >= sourceVa || (sourceVa - targetVa) > 8) {
		return false;
	}
	if (!isOriginalVaPadding(targetVa, patchSize)) {
		return false;
	}
	if (instructionRva < sectionRVA) {
		return false;
	}
	const size_t sourceOffset = instructionRva - sectionRVA;
	if (sourceOffset + 2 > codeSize || !startsWithFlowTransfer(patchedCode + sourceOffset, 2)) {
		return false;
	}
	if (!isFunctionEntry(instructionRva)) {
		return false;
	}
	BYTE targetCode[8] = { 0 };
	const size_t read = readCurrentBytes(targetVa, targetCode, sizeof(targetCode));
	if (!read || !startsWithFlowTransfer(targetCode, read)) {
		return false;
	}
	return true;
}

PatchInjectionContext pesieve::PatchAnalyzer::makePatchContext(PatchList::Patch& patch, DWORD instructionRva, size_t patchSize) const
{
	PatchInjectionContext context;
	context.sourceVa = moduleData.rvaToVa(instructionRva);
	context.patchRva = patch.startRva;
	context.instructionRva = instructionRva;
	context.patchSize = (uint32_t)patchSize;
	context.moduleName = moduleData.szModName;

	if (instructionRva < sectionRVA) {
		return context;
	}
	const size_t instructionOffset = instructionRva - sectionRVA;
	if (instructionOffset < codeSize) {
		const size_t available = codeSize - instructionOffset;
		size_t evidenceSize = patchSize < 8 ? patchSize : 8;
		if (evidenceSize > available) evidenceSize = available;
		context.opcode = patchedCode[instructionOffset];
		if (evidenceSize > 1) {
			context.opcode2 = patchedCode[instructionOffset + 1];
		}
		context.currentBytes = bytesToHex(patchedCode + instructionOffset, evidenceSize);
		if (instructionRva < moduleData.original_size) {
			const size_t origAvailable = moduleData.original_size - instructionRva;
			size_t origEvidenceSize = evidenceSize < origAvailable ? evidenceSize : origAvailable;
			context.sourceBytes = bytesToHex(moduleData.original_module + instructionRva, origEvidenceSize);
		}
	}
	context.sourceWasPadding = isOriginalRangePadding(instructionRva, patchSize);
	context.sourceAtFunctionEntry = isFunctionEntry(instructionRva);
	context.classicHotpatch = isClassicHotpatchSlot(instructionRva, patchSize);

	const ULONGLONG targetVa = patch.getHookTargetVA();
	context.hasTarget = (targetVa != 0);
	context.targetVa = targetVa;
	if (context.hasTarget) {
		const ULONGLONG moduleBase = (ULONGLONG)moduleData.moduleHandle;
		context.targetSameModule = targetVa >= moduleBase && targetVa < (moduleBase + moduleData.original_size);
		context.targetInNamedModule = context.targetSameModule && (moduleData.szModName[0] != 0);
		context.targetWasPadding = context.targetSameModule && isOriginalVaPadding(targetVa, 8);
		context.targetBeforeSource = targetVa < context.sourceVa;
		context.classicHotpatch = context.classicHotpatch || isHotpatchEntryJump(instructionRva, patchSize, targetVa);

		BYTE targetCode[32] = { 0 };
		const size_t read = readCurrentBytes(targetVa, targetCode, sizeof(targetCode));
		if (read) {
			context.targetStartsFlowTransfer = startsWithFlowTransfer(targetCode, read);
			context.targetBytes = bytesToHex(targetCode, read < 8 ? read : 8);
			if (context.targetSameModule) {
				context.targetHasCopiedPrologue = targetHasCopiedPrologue(targetCode, read, instructionRva, patchSize);
			}
			const ULONGLONG afterPatchVa = context.sourceVa + patchSize;
			context.targetHasJumpBack = containsJumpBack(targetCode, read, targetVa, afterPatchVa);
		}
	}
	return context;
}

size_t pesieve::PatchAnalyzer::parseShortJmp(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 2;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size)) {
		return 0;
	}
	BYTE *lval = reinterpret_cast<BYTE*>((ULONG_PTR)patch_ptr + 1);
	ULONGLONG addr = getJmpDestAddr<int8_t>(patch_va, instr_size, (int8_t)(*lval));

	patch.setHookTarget(addr);
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseJmp(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size)) {
		return 0;
	}
	DWORD *lval = reinterpret_cast<DWORD*>((ULONG_PTR) patch_ptr + 1);
	ULONGLONG addr = getJmpDestAddr<DWORD>(patch_va, instr_size, (*lval));

	patch.setHookTarget(addr);
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseJmpViaAddr(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va)
{
	const size_t instr_size = 6;
	
	DWORD *lval = reinterpret_cast<DWORD*>((ULONG_PTR)patch_ptr + 2);
	if (!isModule64bit) { //32bit
		patch.setHookTarget(*lval, false);
	}
	else { //64bit
		ULONGLONG addr = getJmpDestAddr<DWORD>(patch_va, instr_size, (*lval));
		patch.setHookTarget(addr, false);
	}
	return instr_size;
}

size_t pesieve::PatchAnalyzer::parseMovJmp(PatchList::Patch &patch, BYTE* patch_ptr, bool is_long)
{
	size_t mov_instr_len = is_long ? 9 : 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, mov_instr_len + 2)) {
		return 0;
	}

	BYTE* jmp_ptr = patch_ptr + mov_instr_len; // next instruction
	if (is64Modifier(*patch_ptr)) {
		patch_ptr++;
		jmp_ptr++;
		mov_instr_len++; // add length of modifier
	}
	
	DWORD reg_id0 = patch_ptr[0] - 0xB8;

	// before call/jmp there can be also the modifier...
	if (is64Modifier(*jmp_ptr)) {
		jmp_ptr++;
		mov_instr_len++; // add length of modifier
	}
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, jmp_ptr, 2)) {
		return 0;
	}
	DWORD reg_id1 = 0;
	if (jmp_ptr[0] == 0xFF && jmp_ptr[1] >= 0xE0 && jmp_ptr[1] <= 0xEF ) { // jmp reg
		//jmp reg
		reg_id1 = jmp_ptr[1] - 0xE0;
	} else if (jmp_ptr[0] == 0xFF && jmp_ptr[1] >= 0xD0 && jmp_ptr[1] <= 0xDF ) { // call reg
		//jmp reg
		reg_id1 = jmp_ptr[1] - 0xD0;
	} else {
#ifdef _DEBUG
		std::cerr << "It is not MOV->JMP" << std::hex << (DWORD)jmp_ptr[0] << std::endl;
#endif
		return 0;
	}
	//TODO: take into account also modifiers
	if (reg_id1 != reg_id0) {
#ifdef _DEBUG
		std::cerr << "MOV->JMP : reg mismatch" << std::endl;
#endif
		return 0;
	}
	size_t patch_size = mov_instr_len;
	ULONGLONG addr = 0;
	if (!is_long) { //32bit
		DWORD *lval = reinterpret_cast<DWORD*>((ULONG_PTR) patch_ptr + 1);
		addr = *lval;
	} else { //64bit
		ULONGLONG *lval = reinterpret_cast<ULONGLONG*>((ULONG_PTR) patch_ptr + 1);
		addr = *lval;
	}
	patch_size += 2; //add jump reg size
	patch.setHookTarget(addr);
#ifdef _DEBUG
	std::cout << "----> Target: " << std::hex << addr << std::endl;
#endif
	return patch_size;
}

size_t pesieve::PatchAnalyzer::parsePushRet(PatchList::Patch &patch, BYTE* patch_ptr)
{
	size_t instr_size = 5;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, instr_size + 1)) {
		return 0;
	}
	BYTE* ret_ptr = reinterpret_cast<BYTE*>((ULONG_PTR) patch_ptr + instr_size); // next instruction
	if (ret_ptr[0] != 0xC3) {
		return 0; // this is not push->ret
	}
	instr_size++;
	DWORD *lval = reinterpret_cast<DWORD*>((ULONG_PTR) patch_ptr + 1);
	patch.setHookTarget(*lval);
	return instr_size;
}

bool pesieve::PatchAnalyzer::is64Modifier(BYTE op)
{
	if (!isModule64bit) return false;
	if (op >= 0x40 && op <= 0x4F) { // modifier
		return true;
	}
	return false;
}

bool pesieve::PatchAnalyzer::isLongModifier(BYTE op)
{
	if (!isModule64bit) return false;
	if (op >= 0x48 && op <= 0x4F) { // modifier
		return true;
	}
	return false;
}

size_t pesieve::PatchAnalyzer::_analyzeHook(PatchList::Patch &patch, BYTE* patch_ptr, ULONGLONG patch_va)
{
	BYTE op = patch_ptr[0];
	if (op == OP_JMP || op == OP_CALL_DWORD) {
		return parseJmp(patch, patch_ptr, patch_va);
	}
	if (op == OP_SHORTJMP) {
		return parseShortJmp(patch, patch_ptr, patch_va);
	}
	if (op == OP_PUSH_DWORD) {
		return parsePushRet(patch, patch_ptr);
	}
	if (op == OP_JMP_VIA_ADDR_B1 && patch_ptr[1] == OP_JMP_VIA_ADDR_B2) {
		return parseJmpViaAddr(patch, patch_ptr, patch_va);
	}

	bool is_long = false;
	if (is64Modifier(op)) { // mov modifier
		if (isLongModifier(op)) {
			is_long = true;
		}
		op = patch_ptr[1];
	}

	if (op >= 0xB8 && op <= 0xBF) { // is mov
		return parseMovJmp(patch, patch_ptr, is_long);
	}
	return 0;
}

size_t pesieve::PatchAnalyzer::_analyzeRelocated(PatchList::Patch &patch, BYTE* patch_ptr)
{
	if (this->relocs.find(patch.startRva) == this->relocs.end()) {
		return 0;
	}
	// This patch is a relocated field
	const size_t fieldSize = (this->moduleData.is64bit()) ? sizeof(ULONGLONG) : sizeof(DWORD);
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, fieldSize)) {
		return 0;
	}
	ULONGLONG field = (this->moduleData.is64bit()) ? *((ULONGLONG*)patch_ptr) : *((DWORD*)patch_ptr);
	patch.setHookTarget(field, true, pesieve::HOOK_ADDR_REPLACEMENT);
	return fieldSize;
}

size_t pesieve::PatchAnalyzer::analyzeOther(PatchList::Patch& patch)
{
	const size_t patch_offset = patch.startRva - sectionRVA;
	BYTE* patch_ptr = this->patchedCode + patch_offset;
	size_t size = patch.endRva - patch.startRva;

	if (size > 1) {
		bool isPadding = true;
		for (size_t i = 1; i < size; ++i) {
			if (patch_ptr[0] != patch_ptr[i]) {
				isPadding = false;
			}
		}
		if (isPadding) {
			patch.type = PATCH_PADDING;
			patch.paddingVal = patch_ptr[0];
		}
	}
	if (patch_ptr[0] == 0xCC) {
		if (size == 1 || patch.type == PATCH_PADDING) {
			patch.type = PATCH_BREAKPOINT;
		}
	}

	PatchInjectionContext context;
	context.sourceVa = moduleData.rvaToVa(patch.startRva);
	context.patchRva = patch.startRva;
	context.instructionRva = patch.startRva;
	context.patchSize = (uint32_t)size;
	context.moduleName = moduleData.szModName;
	context.sourceWasPadding = isOriginalRangePadding(patch.startRva, size);
	context.sourceAtFunctionEntry = isFunctionEntry(patch.startRva);
	context.isPaddingPatch = (patch.type == PATCH_PADDING);
	context.isBreakpoint = (patch.type == PATCH_BREAKPOINT);

	const size_t evidenceSize = size < 8 ? size : 8;
	context.currentBytes = bytesToHex(patch_ptr, evidenceSize);
	if (patch.startRva < moduleData.original_size) {
		const size_t available = moduleData.original_size - patch.startRva;
		const size_t origSize = evidenceSize < available ? evidenceSize : available;
		context.sourceBytes = bytesToHex(moduleData.original_module + patch.startRva, origSize);
	}
	patch.setInjectionContext(context);
	return size;
}

size_t pesieve::PatchAnalyzer::analyzeHook(PatchList::Patch &patch)
{
	const ULONGLONG patch_va = moduleData.rvaToVa(patch.startRva);
	const size_t patch_offset = patch.startRva - sectionRVA;
	BYTE* patch_ptr = this->patchedCode + patch_offset;

	size_t size = _analyzeRelocated(patch, patch_ptr);
	if (size) {
		PatchInjectionContext context;
		context.sourceVa = patch_va;
		context.patchRva = patch.startRva;
		context.instructionRva = patch.startRva;
		context.patchSize = (uint32_t)size;
		context.moduleName = moduleData.szModName;
		context.isRelocatedField = true;
		context.currentBytes = bytesToHex(patch_ptr, size);
		if (patch.startRva < moduleData.original_size) {
			const size_t available = moduleData.original_size - patch.startRva;
			const size_t origSize = size < available ? size : available;
			context.sourceBytes = bytesToHex(moduleData.original_module + patch.startRva, origSize);
		}
		patch.setInjectionContext(context);
		return size;
	}
	const size_t kMinSize = 3;
	if (!peconv::validate_ptr(this->patchedCode, this->codeSize, patch_ptr, kMinSize)) {
		return 0;
	}
	size = _analyzeHook(patch, patch_ptr, patch_va);
	DWORD instructionRva = patch.startRva;
	if (size == 0 && patch_offset > 0) {
		//it may happen that the address of an existing JMP/CALL was replaced
		//try to parse a byte before the patch...
		size = _analyzeHook(patch, patch_ptr -1, patch_va - 1);
		if (size > 0) {
			// subtract the added position:
			size--;
			instructionRva--;
		}
	}
	if (size > 0) {
		patch.setInjectionContext(makePatchContext(patch, instructionRva, size));
	}
	return size;
}

