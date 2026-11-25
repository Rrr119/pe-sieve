#include "headers_scanner.h"
#include <peconv.h>

using namespace pesieve;

HeadersScanReport* pesieve::HeadersScanner::scanRemote()
{
	if (!moduleData.isInitialized() && !moduleData.loadOriginal()) {
		std::cerr << "[-] Module not initialized" << std::endl;
		return nullptr;
	}
	if (!remoteModData.isInitialized()) {
		std::cerr << "[-] Failed to read the module header" << std::endl;
		return nullptr;
	}

	HeadersScanReport *my_report = new HeadersScanReport(moduleData.moduleHandle, remoteModData.getModuleSize());

	BYTE hdr_buffer1[peconv::MAX_HEADER_SIZE] = { 0 };
	memcpy(hdr_buffer1, remoteModData.headerBuffer, peconv::MAX_HEADER_SIZE);
	my_report->is64 = peconv::is64bit(hdr_buffer1);
	my_report->isDotNetModule = moduleData.isDotNet();
	my_report->origBase = moduleData.getHdrImageBase();
	my_report->relocBase = remoteModData.getHdrImageBase();

	size_t hdrs_size = peconv::get_hdrs_size(hdr_buffer1);
	if (hdrs_size > peconv::MAX_HEADER_SIZE) {
		hdrs_size = peconv::MAX_HEADER_SIZE;
	}

	BYTE hdr_buffer2[peconv::MAX_HEADER_SIZE] = { 0 };
	memcpy(hdr_buffer2, moduleData.original_module, hdrs_size);

	// some .NET modules overwrite their own headers, so at this point they should be excluded from the comparison
	const DWORD ep1 = peconv::get_entry_point_rva(hdr_buffer1);
	const DWORD ep2 = peconv::get_entry_point_rva(hdr_buffer2);
	my_report->actualEntryPoint = ep1;
	my_report->expectedEntryPoint = ep2;
	if (ep1 != ep2) {
		my_report->epModified = true;
	}
	const DWORD arch1 = peconv::get_nt_hdr_architecture(hdr_buffer1);
	const DWORD arch2 = peconv::get_nt_hdr_architecture(hdr_buffer2);
	if (arch1 != arch2) {
		// this often happend in .NET modules
		//if there is an architecture mismatch it may indicate that a different version of the app was loaded (possibly legit)
		my_report->archMismatch = true;
	}

	//normalize before comparing:
	peconv::update_image_base(hdr_buffer1, 0);
	peconv::update_image_base(hdr_buffer2, 0);

	zeroUnusedFields(hdr_buffer1, hdrs_size);
	zeroUnusedFields(hdr_buffer2, hdrs_size);

	//compare:
	if (memcmp(hdr_buffer1, hdr_buffer2, hdrs_size) == 0) {
		my_report->status = SCAN_NOT_SUSPICIOUS;
		HeaderInjectionContext injectionContext;
		my_report->injection = classifyModuleInjection(injectionContext);
		return my_report;
	}
	//modifications detected, now find more details:
	my_report->dosHdrModified = isDosHdrModified(hdr_buffer1, hdr_buffer2, hdrs_size);
	my_report->fileHdrModified = isFileHdrModified(hdr_buffer1, hdr_buffer2, hdrs_size);
	my_report->ntHdrModified = isNtHdrModified(hdr_buffer1, hdr_buffer2, hdrs_size);
	my_report->secHdrModified = isSecHdrModified(hdr_buffer1, hdr_buffer2, hdrs_size, &my_report->sectionDifferences);

	HeaderInjectionContext injectionContext;
	injectionContext.sectionTableModified = my_report->isHdrReplaced();
	injectionContext.entryPointModified = my_report->epModified;
	injectionContext.ntHeadersModified = my_report->ntHdrModified;
	injectionContext.fileHeadersModified = my_report->fileHdrModified;
	injectionContext.dosHeaderModified = my_report->dosHdrModified;
	injectionContext.architectureMismatch = my_report->archMismatch;
	injectionContext.sectionDifferences = my_report->sectionDifferences;
	my_report->injection = classifyModuleInjection(injectionContext);

	if (moduleData.isDotNet()) {
		const bool dotNetFileHdrModif = isFileHdrModified(hdr_buffer1, hdr_buffer2, hdrs_size, my_report->archMismatch);
#ifdef _DEBUG
		std::cout << "[#] .NET module detected as SUSPICIOUS\n";
#endif
		if (!my_report->isHdrReplaced()
			&& !my_report->dosHdrModified
			&& !dotNetFileHdrModif
			&& (my_report->epModified || (my_report->archMismatch && my_report->ntHdrModified))
			)
		{
			//.NET modules may overwrite some parts of their own headers
#ifdef _DEBUG
			std::cout << "[#] Filtered out modifications typical for .NET files, setting as not suspicious\n";
#endif
			my_report->status = SCAN_NOT_SUSPICIOUS;
			my_report->injection.reset();
			my_report->injection.type = INJECTION_NONE;
			my_report->injection.verdict = INJECTION_VERDICT_BENIGN;
			my_report->injection.confidence = 90;
			my_report->injection.reason = "dotnet_header_changes_filtered";
			return my_report;
		}
	}
	my_report->status = SCAN_SUSPICIOUS;
	return my_report;
}

bool pesieve::HeadersScanner::zeroUnusedFields(PBYTE hdr_buffer, size_t hdrs_size)
{
	bool is_modified = false;
	const size_t section_num = peconv::get_sections_count(hdr_buffer, hdrs_size);

	for (size_t i = 0; i < section_num; i++) {
		PIMAGE_SECTION_HEADER sec_hdr = peconv::get_section_hdr(hdr_buffer, hdrs_size, i);
		if (sec_hdr == nullptr) continue;

		if (sec_hdr->SizeOfRawData == 0) {
			sec_hdr->PointerToRawData = 0;
			is_modified = true;
		}
	}
	return is_modified;
}

bool pesieve::HeadersScanner::isDosHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size)
{
	if (hdrs_size < sizeof(IMAGE_DOS_HEADER)) { //should never happen
		return false;
	}
	IMAGE_DOS_HEADER* hdr1 = (IMAGE_DOS_HEADER*)hdr_buffer1;
	IMAGE_DOS_HEADER* hdr2 = (IMAGE_DOS_HEADER*)hdr_buffer2;
	if (memcmp(hdr1, hdr2, sizeof(IMAGE_DOS_HEADER)) != 0) {
		return true;
	}

	LONG new_hdr = hdr2->e_lfanew;
	if (memcmp(hdr1, hdr2, new_hdr) != 0) {
		return true;
	}
	return false;
}

bool pesieve::HeadersScanner::isSecHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size, std::vector<std::string>* differences)
{
	size_t section_num1 = peconv::get_sections_count(hdr_buffer1, hdrs_size);
	size_t section_num2 = peconv::get_sections_count(hdr_buffer2, hdrs_size);
	if (section_num1 != section_num2) {
		if (differences) {
			std::stringstream ss;
			ss << "section_count expected=" << std::dec << section_num2 << " actual=" << section_num1;
			differences->push_back(ss.str());
		}
		return true;
	}

	bool modified = false;
	for (size_t i = 0; i < section_num1; i++) {
		PIMAGE_SECTION_HEADER sec_hdr1 = peconv::get_section_hdr(hdr_buffer1, hdrs_size, i);
		PIMAGE_SECTION_HEADER sec_hdr2 = peconv::get_section_hdr(hdr_buffer2, hdrs_size, i);
		if (!sec_hdr1 && !sec_hdr2) {
			continue;
		}
		else if (!sec_hdr1 || !sec_hdr2) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << "] missing in one of the images";
				differences->push_back(ss.str());
			}
			modified = true;
			continue;
		}

		const size_t name_len = strnlen((const char*)sec_hdr1->Name, IMAGE_SIZEOF_SHORT_NAME);
		const std::string section_name((const char*)sec_hdr1->Name, name_len);
		const size_t name_len2 = strnlen((const char*)sec_hdr2->Name, IMAGE_SIZEOF_SHORT_NAME);
		const std::string section_name2((const char*)sec_hdr2->Name, name_len2);
		if (section_name != section_name2) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << "] name expected=" << section_name2
					<< " actual=" << section_name;
				differences->push_back(ss.str());
			}
			modified = true;
		}
		if (sec_hdr1->VirtualAddress != sec_hdr2->VirtualAddress) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << ":" << section_name << "] VirtualAddress expected=0x"
					<< std::hex << sec_hdr2->VirtualAddress << " actual=0x" << sec_hdr1->VirtualAddress;
				differences->push_back(ss.str());
			}
			modified = true;
		}
		if (sec_hdr1->Misc.VirtualSize != sec_hdr2->Misc.VirtualSize) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << ":" << section_name << "] VirtualSize expected=0x"
					<< std::hex << sec_hdr2->Misc.VirtualSize << " actual=0x" << sec_hdr1->Misc.VirtualSize;
				differences->push_back(ss.str());
			}
			modified = true;
		}
		if (sec_hdr1->SizeOfRawData != sec_hdr2->SizeOfRawData) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << ":" << section_name << "] SizeOfRawData expected=0x"
					<< std::hex << sec_hdr2->SizeOfRawData << " actual=0x" << sec_hdr1->SizeOfRawData;
				differences->push_back(ss.str());
			}
			modified = true;
		}
		if (sec_hdr1->PointerToRawData != sec_hdr2->PointerToRawData) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << ":" << section_name << "] PointerToRawData expected=0x"
					<< std::hex << sec_hdr2->PointerToRawData << " actual=0x" << sec_hdr1->PointerToRawData;
				differences->push_back(ss.str());
			}
			modified = true;
		}
		if (sec_hdr1->Characteristics != sec_hdr2->Characteristics) {
			if (differences) {
				std::stringstream ss;
				ss << "section[" << std::dec << i << ":" << section_name << "] Characteristics expected=0x"
					<< std::hex << sec_hdr2->Characteristics << " actual=0x" << sec_hdr1->Characteristics;
				differences->push_back(ss.str());
			}
			modified = true;
		}
	}
	return modified;
}

bool pesieve::HeadersScanner::isFileHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size, bool mask_arch_mismatch)
{
	const IMAGE_FILE_HEADER *file_hdr1 = peconv::get_file_hdr(hdr_buffer1, hdrs_size);
	const IMAGE_FILE_HEADER *file_hdr2 = peconv::get_file_hdr(hdr_buffer2, hdrs_size);

	if (!file_hdr1 && !file_hdr2) return false;
	if (!file_hdr1 || !file_hdr2) return true;

	if (memcmp(file_hdr1, file_hdr2, sizeof(IMAGE_FILE_HEADER)) == 0) {
		return false;
	}
	if (mask_arch_mismatch) {
		if (file_hdr1->Machine == file_hdr2->Machine
			&& file_hdr1->Characteristics == file_hdr2->Characteristics
			&& file_hdr1->NumberOfSections == file_hdr2->NumberOfSections
			&& file_hdr1->TimeDateStamp == file_hdr2->TimeDateStamp
			&& file_hdr1->SizeOfOptionalHeader != file_hdr2->SizeOfOptionalHeader)
		{
			// only the SizeOfOptionalHeader has changed
			return false;
		}
	}
	return true;
}

bool pesieve::HeadersScanner::isNtHdrModified(const PBYTE hdr_buffer1, const PBYTE hdr_buffer2, const size_t hdrs_size)
{
	const bool is64 = peconv::is64bit(hdr_buffer1);
	if (peconv::is64bit(hdr_buffer2) != is64) {
		return true;
	}
	const BYTE *nt1 = peconv::get_nt_hdrs(hdr_buffer1, hdrs_size);
	const BYTE *nt2 = peconv::get_nt_hdrs(hdr_buffer2, hdrs_size);
	if (!nt1 && !nt2) return false;
	if (!nt1 || !nt2) return true;

	const size_t nt_hdr_size = is64 ? sizeof(IMAGE_NT_HEADERS64) : sizeof(IMAGE_NT_HEADERS32);
	if (memcmp(nt1, nt2, nt_hdr_size) == 0) {
		return false;
	}
	return true;
}
