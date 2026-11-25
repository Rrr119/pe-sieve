#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

namespace pesieve {

	//! Fine-grained classification of the source of a code modification.
	typedef enum {
		INJECTION_NONE = 0,
		INJECTION_UNKNOWN,
		INJECTION_MODULE_REPLACEMENT,
		INJECTION_CODE_CAVE,
		INJECTION_SHELLCODE_JUMP,
		INJECTION_HOTPATCH,
		INJECTION_INLINE_HOOK,
		INJECTION_TYPES_COUNT
	} t_injection_type;

	typedef enum {
		INJECTION_VERDICT_UNKNOWN = 0,
		INJECTION_VERDICT_BENIGN,
		INJECTION_VERDICT_SUSPICIOUS,
		INJECTION_VERDICT_INJECTED,
		INJECTION_VERDICTS_COUNT
	} t_injection_verdict;

	const char* injection_type_to_id(const t_injection_type type);
	const char* injection_verdict_to_id(const t_injection_verdict verdict);
	bool is_injection_type(const t_injection_type type);

	//! A single machine-readable fact supporting an injection verdict.
	struct InjectionEvidence {
		InjectionEvidence()
		{
		}

		InjectionEvidence(const std::string& _kind, const std::string& _value, const std::string& _detail = "")
			: kind(_kind), value(_value), detail(_detail)
		{
		}

		std::string kind;
		std::string value;
		std::string detail;
	};

	//! The type, verdict, confidence and evidence produced by the classifier.
	struct InjectionAssessment {
		InjectionAssessment()
		{
			reset();
		}

		void reset()
		{
			type = INJECTION_NONE;
			verdict = INJECTION_VERDICT_UNKNOWN;
			confidence = 0;
			reason.clear();
			evidence.clear();
		}

		bool isInjection() const
		{
			return verdict == INJECTION_VERDICT_INJECTED && is_injection_type(type);
		}

		void addEvidence(const std::string& kind, const std::string& value, const std::string& detail = "")
		{
			evidence.push_back(InjectionEvidence(kind, value, detail));
		}

		//! Serializes the assessment as a self-contained JSON object. Existing report fields are not touched.
		bool toJSON(std::stringstream& outs, size_t level) const;

		t_injection_type type;
		t_injection_verdict verdict;
		unsigned int confidence;
		std::string reason;
		std::vector<InjectionEvidence> evidence;
	};

	//! Features collected while parsing one code patch.
	struct PatchInjectionContext {
		PatchInjectionContext()
			: sourceVa(0),
			patchRva(0), instructionRva(0), patchSize(0),
			opcode(0), opcode2(0),
			indirect(false),
			isRelocatedField(false),
			isPaddingPatch(false),
			isBreakpoint(false),
			isImportThunk(false),
			sourceWasPadding(false),
			sourceAtFunctionEntry(false),
			sectionExpanded(false),
			classicHotpatch(false),
			hasTarget(false),
			targetResolved(false),
			targetSameModule(false),
			targetInNamedModule(false),
			targetInSuspiciousModule(false),
			targetWasPadding(false),
			targetStartsFlowTransfer(false),
			targetHasCopiedPrologue(false),
			targetHasJumpBack(false),
			targetBeforeSource(false),
			targetVa(0)
		{
		}

		std::uint64_t sourceVa;
		std::uint32_t patchRva;
		std::uint32_t instructionRva;
		std::uint32_t patchSize;
		unsigned char opcode;
		unsigned char opcode2;
		bool indirect;

		bool isRelocatedField;
		bool isPaddingPatch;
		bool isBreakpoint;
		bool isImportThunk;
		bool sourceWasPadding;
		bool sourceAtFunctionEntry;
		bool sectionExpanded;
		bool classicHotpatch;

		bool hasTarget;
		bool targetResolved;
		bool targetSameModule;
		bool targetInNamedModule;
		bool targetInSuspiciousModule;
		bool targetWasPadding;
		bool targetStartsFlowTransfer;
		bool targetHasCopiedPrologue;
		bool targetHasJumpBack;
		bool targetBeforeSource;
		std::uint64_t targetVa;

		std::string moduleName;
		std::string targetModuleName;
		std::string sourceBytes;
		std::string currentBytes;
		std::string targetBytes;
	};

	//! Features collected while comparing a loaded PE header with the file on disk.
	struct HeaderInjectionContext {
		HeaderInjectionContext()
			: sectionTableModified(false),
			entryPointModified(false),
			ntHeadersModified(false),
			fileHeadersModified(false),
			dosHeaderModified(false),
			architectureMismatch(false),
			mappingMismatch(false),
			sectionExpanded(false)
		{
		}

		bool sectionTableModified;
		bool entryPointModified;
		bool ntHeadersModified;
		bool fileHeadersModified;
		bool dosHeaderModified;
		bool architectureMismatch;
		bool mappingMismatch;
		bool sectionExpanded;
		std::vector<std::string> sectionDifferences;
	};

	InjectionAssessment classifyPatchInjection(const PatchInjectionContext& context);
	InjectionAssessment classifyModuleInjection(const HeaderInjectionContext& context);
	InjectionAssessment classifyThreadInjection(bool ipOutsideModule, bool stackFrameOutsideModule, bool returnAddressOutsideModule);

}; //namespace pesieve
