#include "injection_classifier.h"

#include <iomanip>

using namespace pesieve;

namespace {

	void indent(std::stringstream& outs, size_t level)
	{
		for (size_t i = 0; i < level; i++) {
			outs << "  ";
		}
	}

	std::string escape_json(const std::string& value)
	{
		static const char hex[] = "0123456789abcdef";
		std::string escaped;
		escaped.reserve(value.size());
		for (unsigned char ch : value) {
			switch (ch) {
			case '"': escaped += "\\\""; break;
			case '\\': escaped += "\\\\"; break;
			case '\n': escaped += "\\n"; break;
			case '\r': escaped += "\\r"; break;
			case '\t': escaped += "\\t"; break;
			default:
				if (ch < 0x20) {
					escaped += "\\u00";
					escaped += hex[ch >> 4];
					escaped += hex[ch & 0x0f];
				}
				else {
					escaped += static_cast<char>(ch);
				}
			}
		}
		return escaped;
	}

	std::string hex_value(std::uint64_t value)
	{
		std::stringstream ss;
		ss << "0x" << std::hex << value;
		return ss.str();
	}

	std::string bool_value(bool value)
	{
		return value ? "true" : "false";
	}

	void add_patch_evidence(InjectionAssessment& assessment, const PatchInjectionContext& context)
	{
		assessment.addEvidence("patch_rva", hex_value(context.patchRva));
		if (context.patchSize) {
			std::stringstream size;
			size << std::dec << context.patchSize;
			assessment.addEvidence("patch_size", size.str());
		}
		if (context.opcode) {
			std::stringstream op;
			op << "0x" << std::hex << (unsigned int)context.opcode;
			if (context.opcode2) {
				op << " 0x" << std::hex << (unsigned int)context.opcode2;
			}
			assessment.addEvidence("opcode", op.str());
		}
		if (!context.sourceBytes.empty()) {
			assessment.addEvidence("original_bytes", context.sourceBytes);
		}
		if (!context.currentBytes.empty()) {
			assessment.addEvidence("current_bytes", context.currentBytes);
		}
		if (!context.moduleName.empty()) {
			assessment.addEvidence("source_module", context.moduleName);
		}
		if (context.sourceWasPadding) {
			assessment.addEvidence("source_was_padding", bool_value(true),
				"the modified bytes were unused padding in the file-backed image");
		}
		if (context.sectionExpanded) {
			assessment.addEvidence("section_expanded", bool_value(true),
				"the loaded section is larger than the file-backed section");
		}
		if (context.sourceAtFunctionEntry) {
			assessment.addEvidence("source_at_function_entry", bool_value(true),
				"the patch starts at an entry point, export or a typical function prologue");
		}
		if (context.classicHotpatch) {
			assessment.addEvidence("classic_hotpatch_layout", bool_value(true),
				"entry jump and the preceding five-byte hotpatch slot form a hotpatch trampoline");
		}
		if (context.isRelocatedField) {
			assessment.addEvidence("relocation_entry", bool_value(true),
				"the changed bytes belong to the module relocation table");
		}
		if (context.hasTarget) {
			assessment.addEvidence("target_va", hex_value(context.targetVa));
			if (context.indirect) {
				assessment.addEvidence("target_indirect", bool_value(true));
			}
			assessment.addEvidence("target_same_module", bool_value(context.targetSameModule));
			assessment.addEvidence("target_in_named_module", bool_value(context.targetInNamedModule));
			if (!context.targetModuleName.empty()) {
				assessment.addEvidence("target_module", context.targetModuleName);
			}
			else {
				assessment.addEvidence("target_module", "", "the target is not backed by any scanned named module");
			}
			if (context.targetInSuspiciousModule) {
				assessment.addEvidence("target_module_suspicious", bool_value(true));
			}
			if (context.targetWasPadding) {
				assessment.addEvidence("target_was_padding", bool_value(true),
					"the flow target was unused padding in the file-backed image");
			}
			if (context.targetStartsFlowTransfer) {
				assessment.addEvidence("target_starts_flow_transfer", bool_value(true));
			}
			if (context.targetHasCopiedPrologue) {
				assessment.addEvidence("target_has_copied_prologue", bool_value(true),
					"the target starts with the original prologue of the patched function");
			}
			if (context.targetHasJumpBack) {
				assessment.addEvidence("target_has_jump_back", bool_value(true),
					"the target contains a jump back to the instruction after the patch");
			}
			if (context.targetBeforeSource) {
				assessment.addEvidence("target_before_source", bool_value(true));
			}
			if (!context.targetBytes.empty()) {
				assessment.addEvidence("target_bytes", context.targetBytes);
			}
		}
	}

}; //namespace

const char* pesieve::injection_type_to_id(const t_injection_type type)
{
	switch (type) {
	case INJECTION_NONE: return "none";
	case INJECTION_UNKNOWN: return "unknown";
	case INJECTION_MODULE_REPLACEMENT: return "module_replacement";
	case INJECTION_CODE_CAVE: return "code_cave";
	case INJECTION_SHELLCODE_JUMP: return "shellcode_jump";
	case INJECTION_HOTPATCH: return "hotpatch";
	case INJECTION_INLINE_HOOK: return "inline_hook";
	default: return "unknown";
	}
}

const char* pesieve::injection_verdict_to_id(const t_injection_verdict verdict)
{
	switch (verdict) {
	case INJECTION_VERDICT_UNKNOWN: return "unknown";
	case INJECTION_VERDICT_BENIGN: return "benign";
	case INJECTION_VERDICT_SUSPICIOUS: return "suspicious";
	case INJECTION_VERDICT_INJECTED: return "injected";
	default: return "unknown";
	}
}

bool pesieve::is_injection_type(const t_injection_type type)
{
	switch (type) {
	case INJECTION_MODULE_REPLACEMENT:
	case INJECTION_CODE_CAVE:
	case INJECTION_SHELLCODE_JUMP:
		return true;
	default:
		return false;
	}
}

bool pesieve::InjectionAssessment::toJSON(std::stringstream& outs, size_t level) const
{
	indent(outs, level);
	outs << "\"injection\" : {\n";

	indent(outs, level + 1);
	outs << "\"type\" : \"" << injection_type_to_id(type) << "\",\n";
	indent(outs, level + 1);
	outs << "\"verdict\" : \"" << injection_verdict_to_id(verdict) << "\",\n";
	indent(outs, level + 1);
	outs << "\"confidence\" : " << std::dec << confidence;

	if (!reason.empty()) {
		outs << ",\n";
		indent(outs, level + 1);
		outs << "\"reason\" : \"" << escape_json(reason) << "\"";
	}
	outs << ",\n";
	indent(outs, level + 1);
	outs << "\"evidence\" : [";
	for (size_t i = 0; i < evidence.size(); i++) {
		const InjectionEvidence& item = evidence[i];
		outs << (i ? ",\n" : "\n");
		indent(outs, level + 2);
		outs << "{\"kind\" : \"" << escape_json(item.kind) << "\", \"value\" : \""
			<< escape_json(item.value) << "\"";
		if (!item.detail.empty()) {
			outs << ", \"detail\" : \"" << escape_json(item.detail) << "\"";
		}
		outs << "}";
	}
	if (!evidence.empty()) {
		outs << "\n";
		indent(outs, level + 1);
	}
	outs << "]\n";
	indent(outs, level);
	outs << "}";
	return true;
}

InjectionAssessment pesieve::classifyPatchInjection(const PatchInjectionContext& context)
{
	InjectionAssessment assessment;
	add_patch_evidence(assessment, context);

	// Relocation entries and deliberately cleared fields are expected artifacts, not injections.
	if (context.isRelocatedField) {
		assessment.type = INJECTION_NONE;
		assessment.verdict = INJECTION_VERDICT_BENIGN;
		assessment.confidence = 100;
		assessment.reason = "relocated_address_field";
		return assessment;
	}
	if (context.isImportThunk) {
		assessment.type = INJECTION_NONE;
		assessment.verdict = INJECTION_VERDICT_BENIGN;
		assessment.confidence = 95;
		assessment.reason = "import_table_field";
		return assessment;
	}
	if (context.isPaddingPatch || context.isBreakpoint) {
		assessment.type = INJECTION_NONE;
		assessment.verdict = INJECTION_VERDICT_BENIGN;
		assessment.confidence = 95;
		assessment.reason = context.isBreakpoint ? "debug_breakpoint_patch" : "padding_restored";
		return assessment;
	}
	if (context.classicHotpatch) {
		assessment.type = INJECTION_HOTPATCH;
		assessment.verdict = INJECTION_VERDICT_BENIGN;
		assessment.confidence = 98;
		assessment.reason = "classic_hotpatch_trampoline";
		return assessment;
	}

	if (!context.hasTarget) {
		if (context.sectionExpanded || context.sourceWasPadding) {
			assessment.type = INJECTION_CODE_CAVE;
			assessment.verdict = INJECTION_VERDICT_INJECTED;
			assessment.confidence = context.sectionExpanded ? 95 : 90;
			assessment.reason = context.sectionExpanded
				? "executable_bytes_extend_a_file_backed_section"
				: "executable_code_written_into_unused_padding";
			return assessment;
		}
		assessment.type = INJECTION_UNKNOWN;
		assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
		assessment.confidence = 30;
		assessment.reason = "unrecognized_code_modification";
		return assessment;
	}

	if (context.targetSameModule) {
		if (context.targetWasPadding) {
			if (context.targetHasCopiedPrologue || context.targetHasJumpBack) {
				assessment.type = INJECTION_HOTPATCH;
				assessment.verdict = INJECTION_VERDICT_BENIGN;
				assessment.confidence = 92;
				assessment.reason = "trampoline_copies_the_original_prologue";
			}
			else {
				assessment.type = INJECTION_CODE_CAVE;
				assessment.verdict = INJECTION_VERDICT_INJECTED;
				assessment.confidence = 88;
				assessment.reason = "flow_redirected_into_unused_code_space";
			}
			return assessment;
		}
		if (context.sourceWasPadding && context.targetInNamedModule) {
			assessment.type = INJECTION_HOTPATCH;
			assessment.verdict = INJECTION_VERDICT_BENIGN;
			assessment.confidence = 80;
			assessment.reason = "cave_trampoline_to_named_code";
			return assessment;
		}
		if (context.targetInNamedModule) {
			if (context.sourceAtFunctionEntry) {
				assessment.type = INJECTION_HOTPATCH;
				assessment.verdict = INJECTION_VERDICT_BENIGN;
				assessment.confidence = 88;
				assessment.reason = "function_entry_jump_within_named_module";
			}
			else {
				assessment.type = INJECTION_INLINE_HOOK;
				assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
				assessment.confidence = 65;
				assessment.reason = "mid_function_jump_within_named_module";
			}
			return assessment;
		}
		if (context.sourceAtFunctionEntry) {
			assessment.type = INJECTION_HOTPATCH;
			assessment.verdict = INJECTION_VERDICT_BENIGN;
			assessment.confidence = 70;
			assessment.reason = "function_entry_jump_within_loaded_module";
			return assessment;
		}
		assessment.type = INJECTION_UNKNOWN;
		assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
		assessment.confidence = 35;
		assessment.reason = "jump_inside_unnamed_module";
		return assessment;
	}

	if (context.targetInNamedModule) {
		if (context.targetInSuspiciousModule) {
			assessment.type = INJECTION_SHELLCODE_JUMP;
			assessment.verdict = INJECTION_VERDICT_INJECTED;
			assessment.confidence = 90;
			assessment.reason = "flow_redirected_to_a_suspicious_module";
			return assessment;
		}
		assessment.type = INJECTION_INLINE_HOOK;
		assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
		assessment.confidence = 70;
		assessment.reason = "flow_redirected_to_another_named_module";
		return assessment;
	}

	if (context.targetResolved || context.targetVa) {
		assessment.type = INJECTION_SHELLCODE_JUMP;
		assessment.verdict = INJECTION_VERDICT_INJECTED;
		assessment.confidence = context.targetResolved ? 96 : 85;
		assessment.reason = "flow_target_outside_named_modules";
		return assessment;
	}

	assessment.type = INJECTION_UNKNOWN;
	assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
	assessment.confidence = 25;
	assessment.reason = "unresolved_flow_target";
	return assessment;
}

InjectionAssessment pesieve::classifyModuleInjection(const HeaderInjectionContext& context)
{
	InjectionAssessment assessment;
	if (context.sectionTableModified) {
		assessment.type = INJECTION_MODULE_REPLACEMENT;
		assessment.verdict = INJECTION_VERDICT_INJECTED;
		assessment.confidence = 98;
		assessment.reason = "section_table_differs_from_the_file_backed_image";
		assessment.addEvidence("section_table_modified", bool_value(true),
			"the section count, RVAs, virtual sizes or raw offsets differ from disk");
		for (const std::string& diff : context.sectionDifferences) {
			assessment.addEvidence("section_difference", diff);
		}
		if (context.entryPointModified) {
			assessment.addEvidence("entry_point_modified", bool_value(true));
		}
		if (context.architectureMismatch) {
			assessment.addEvidence("architecture_mismatch", bool_value(true));
		}
		return assessment;
	}

	const bool anyHeaderChange = context.entryPointModified
		|| context.ntHeadersModified
		|| context.fileHeadersModified
		|| context.dosHeaderModified
		|| context.architectureMismatch;
	if (anyHeaderChange || context.mappingMismatch || context.sectionExpanded) {
		assessment.type = INJECTION_UNKNOWN;
		assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
		assessment.confidence = 40;
		assessment.reason = "header_or_mapping_change_without_section_table_replacement";
		if (context.entryPointModified) {
			assessment.addEvidence("entry_point_modified", bool_value(true));
		}
		if (context.ntHeadersModified) {
			assessment.addEvidence("nt_headers_modified", bool_value(true));
		}
		if (context.fileHeadersModified) {
			assessment.addEvidence("file_headers_modified", bool_value(true));
		}
		if (context.dosHeaderModified) {
			assessment.addEvidence("dos_header_modified", bool_value(true));
		}
		if (context.architectureMismatch) {
			assessment.addEvidence("architecture_mismatch", bool_value(true));
		}
		if (context.mappingMismatch) {
			assessment.addEvidence("mapping_mismatch", bool_value(true));
		}
		if (context.sectionExpanded) {
			assessment.addEvidence("section_expanded", bool_value(true));
		}
		return assessment;
	}

	assessment.type = INJECTION_NONE;
	assessment.verdict = INJECTION_VERDICT_BENIGN;
	assessment.confidence = 100;
	assessment.reason = "headers_match_the_file_backed_image";
	return assessment;
}

InjectionAssessment pesieve::classifyThreadInjection(bool ipOutsideModule, bool stackFrameOutsideModule, bool returnAddressOutsideModule)
{
	InjectionAssessment assessment;
	if (!ipOutsideModule && !stackFrameOutsideModule && !returnAddressOutsideModule) {
		assessment.type = INJECTION_UNKNOWN;
		assessment.verdict = INJECTION_VERDICT_SUSPICIOUS;
		assessment.confidence = 20;
		assessment.reason = "thread_anomaly_without_shellcode_address";
		return assessment;
	}

	assessment.type = INJECTION_SHELLCODE_JUMP;
	assessment.verdict = INJECTION_VERDICT_INJECTED;
	assessment.confidence = ipOutsideModule ? 95 : 88;
	assessment.reason = ipOutsideModule
		? "instruction_pointer_outside_named_modules"
		: "stack_flow_outside_named_modules";
	if (ipOutsideModule) {
		assessment.addEvidence("instruction_pointer_outside_module", bool_value(true));
	}
	if (stackFrameOutsideModule) {
		assessment.addEvidence("callstack_frame_outside_module", bool_value(true));
	}
	if (returnAddressOutsideModule) {
		assessment.addEvidence("return_address_outside_module", bool_value(true));
	}
	return assessment;
}
