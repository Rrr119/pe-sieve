#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "injection_classifier.h"

using namespace pesieve;

namespace {

	struct PatchSample {
		std::string name;
		PatchInjectionContext context;
		t_injection_type expected_type;
		t_injection_verdict expected_verdict;
	};

	struct ModuleSample {
		std::string name;
		HeaderInjectionContext context;
		t_injection_type expected_type;
		t_injection_verdict expected_verdict;
	};

	PatchInjectionContext patch_base(uint32_t index)
	{
		PatchInjectionContext context;
		context.patchRva = 0x1000 + index * 0x10;
		context.instructionRva = context.patchRva;
		context.patchSize = 5;
		context.sourceVa = 0x140000000ULL + context.patchRva;
		context.opcode = 0xE9;
		context.moduleName = "sample.dll";
		return context;
	}

	HeaderInjectionContext header_base(uint32_t index)
	{
		HeaderInjectionContext context;
		std::stringstream diff;
		diff << "section[" << index % 4 << ":.text] VirtualSize expected=0x1000 actual=0x"
			<< std::hex << (0x1000 + index * 0x10);
		context.sectionDifferences.push_back(diff.str());
		return context;
	}

	bool check_assessment(const std::string& name,
		const InjectionAssessment& assessment,
		t_injection_type expected_type,
		t_injection_verdict expected_verdict)
	{
		bool ok = true;
		if (assessment.type != expected_type) {
			std::cerr << "[FAIL] " << name << ": type=" << injection_type_to_id(assessment.type)
				<< " expected=" << injection_type_to_id(expected_type) << "\n";
			ok = false;
		}
		if (assessment.verdict != expected_verdict) {
			std::cerr << "[FAIL] " << name << ": verdict=" << injection_verdict_to_id(assessment.verdict)
				<< " expected=" << injection_verdict_to_id(expected_verdict) << "\n";
			ok = false;
		}
		if (assessment.evidence.empty()) {
			std::cerr << "[FAIL] " << name << ": no evidence emitted\n";
			ok = false;
		}
		if (expected_verdict == INJECTION_VERDICT_BENIGN && assessment.isInjection()) {
			std::cerr << "[FAIL] " << name << ": benign patch classified as injection\n";
			ok = false;
		}
		if (expected_verdict == INJECTION_VERDICT_INJECTED && !assessment.isInjection()) {
			std::cerr << "[FAIL] " << name << ": injection type not marked as injected\n";
			ok = false;
		}
		std::stringstream json;
		assessment.toJSON(json, 0);
		if (json.str().find("\"evidence\"") == std::string::npos) {
			std::cerr << "[FAIL] " << name << ": evidence missing from JSON\n";
			ok = false;
		}
		return ok;
	}

}; //namespace

int main()
{
	std::vector<PatchSample> patch_samples;
	std::vector<ModuleSample> module_samples;
	std::vector<std::pair<std::string, InjectionAssessment>> thread_samples;

	// 25 hotpatch cases: classic hotpatch layout, same-module entry detours and
	// trampoline caves that copy the original prologue.
	for (uint32_t i = 0; i < 25; i++) {
		PatchInjectionContext ctx = patch_base(i);
		if (i % 3 == 0) {
			ctx.classicHotpatch = true;
			ctx.sourceWasPadding = true;
			ctx.hasTarget = true;
			ctx.targetVa = ctx.sourceVa - 5;
			ctx.targetSameModule = true;
			ctx.targetInNamedModule = true;
			ctx.targetWasPadding = true;
			ctx.targetStartsFlowTransfer = true;
			ctx.targetBeforeSource = true;
			ctx.targetResolved = true;
		}
		else if (i % 3 == 1) {
			ctx.sourceAtFunctionEntry = true;
			ctx.hasTarget = true;
			ctx.targetVa = ctx.sourceVa + 0x2000 + i * 0x10;
			ctx.targetSameModule = true;
			ctx.targetInNamedModule = true;
			ctx.targetResolved = true;
		}
		else {
			ctx.hasTarget = true;
			ctx.sourceWasPadding = true;
			ctx.targetVa = ctx.sourceVa + 0x4000 + i * 0x10;
			ctx.targetSameModule = true;
			ctx.targetInNamedModule = true;
			ctx.targetHasCopiedPrologue = true;
			ctx.targetHasJumpBack = true;
			ctx.targetWasPadding = true;
			ctx.targetResolved = true;
		}
		std::stringstream name;
		name << "hotpatch_" << i;
		patch_samples.push_back({ name.str(), ctx, INJECTION_HOTPATCH, INJECTION_VERDICT_BENIGN });
	}

	// 25 code cave cases: executable bytes written into padding, expanded
	// sections, and jumps into unused space without hotpatch trampoline traits.
	for (uint32_t i = 0; i < 25; i++) {
		PatchInjectionContext ctx = patch_base(i + 25);
		if (i % 3 == 0) {
			ctx.hasTarget = false;
			ctx.sourceWasPadding = true;
		}
		else if (i % 3 == 1) {
			ctx.hasTarget = false;
			ctx.sectionExpanded = true;
			ctx.sourceWasPadding = true;
		}
		else {
			ctx.hasTarget = true;
			ctx.targetVa = ctx.sourceVa + 0x3000 + i * 0x10;
			ctx.targetSameModule = true;
			ctx.targetInNamedModule = true;
			ctx.targetWasPadding = true;
			ctx.targetResolved = true;
		}
		std::stringstream name;
		name << "code_cave_" << i;
		patch_samples.push_back({ name.str(), ctx, INJECTION_CODE_CAVE, INJECTION_VERDICT_INJECTED });
	}

	// 25 shellcode jump cases: external/private targets, suspicious named
	// modules, and threads whose IP/return flow is outside named modules.
	for (uint32_t i = 0; i < 25; i++) {
		if (i % 3 == 0) {
			PatchInjectionContext ctx = patch_base(i + 50);
			ctx.hasTarget = true;
			ctx.targetVa = 0x0000000010000000ULL + i * 0x1000;
			ctx.targetResolved = true;
			ctx.targetSameModule = false;
			ctx.targetInNamedModule = false;
			std::stringstream name;
			name << "shellcode_jump_external_" << i;
			patch_samples.push_back({ name.str(), ctx, INJECTION_SHELLCODE_JUMP, INJECTION_VERDICT_INJECTED });
		}
		else if (i % 3 == 1) {
			PatchInjectionContext ctx = patch_base(i + 50);
			ctx.hasTarget = true;
			ctx.targetVa = 0x0000000020000000ULL + i * 0x1000;
			ctx.targetResolved = true;
			ctx.targetSameModule = false;
			ctx.targetInNamedModule = true;
			ctx.targetInSuspiciousModule = true;
			ctx.targetModuleName = "suspicious.dll";
			std::stringstream name;
			name << "shellcode_jump_suspicious_module_" << i;
			patch_samples.push_back({ name.str(), ctx, INJECTION_SHELLCODE_JUMP, INJECTION_VERDICT_INJECTED });
		}
		else {
			std::stringstream name;
			name << "shellcode_jump_thread_" << i;
			InjectionAssessment assessment = classifyThreadInjection(i % 2 == 0, i % 4 == 1, i % 4 == 3);
			thread_samples.push_back(std::make_pair(name.str(), assessment));
		}
	}

	// 25 module replacement cases: section table replacement is the decisive
	// evidence. Cases with only other header/mapping changes must stay unknown,
	// not be promoted to module replacement.
	for (uint32_t i = 0; i < 25; i++) {
		HeaderInjectionContext ctx = header_base(i);
		if (i % 4 == 3) {
			ctx.sectionTableModified = false;
			ctx.entryPointModified = true;
			ctx.ntHeadersModified = true;
			ctx.mappingMismatch = i % 2 != 0;
			std::stringstream name;
			name << "header_change_not_replacement_" << i;
			module_samples.push_back({ name.str(), ctx, INJECTION_UNKNOWN, INJECTION_VERDICT_SUSPICIOUS });
		}
		else {
			ctx.sectionTableModified = true;
			ctx.entryPointModified = (i % 2 == 0);
			ctx.fileHeadersModified = (i % 5 == 0);
			ctx.architectureMismatch = (i % 7 == 0);
			std::stringstream name;
			name << "module_replacement_" << i;
			module_samples.push_back({ name.str(), ctx, INJECTION_MODULE_REPLACEMENT, INJECTION_VERDICT_INJECTED });
		}
	}

	size_t failures = 0;
	size_t total = 0;
	for (const PatchSample& sample : patch_samples) {
		total++;
		const InjectionAssessment assessment = classifyPatchInjection(sample.context);
		if (!check_assessment(sample.name, assessment, sample.expected_type, sample.expected_verdict)) {
			failures++;
		}
	}
	for (const ModuleSample& sample : module_samples) {
		total++;
		const InjectionAssessment assessment = classifyModuleInjection(sample.context);
		if (!check_assessment(sample.name, assessment, sample.expected_type, sample.expected_verdict)) {
			failures++;
		}
	}
	for (const auto& sample : thread_samples) {
		total++;
		if (!check_assessment(sample.first, sample.second, INJECTION_SHELLCODE_JUMP, INJECTION_VERDICT_INJECTED)) {
			failures++;
		}
	}

	if (total != 100) {
		std::cerr << "[FAIL] expected 100 samples, got " << total << "\n";
		failures++;
	}
	if (failures) {
		std::cerr << "Injection classifier regression: " << (total - failures) << "/" << total << " matched\n";
		return 1;
	}
	std::cout << "Injection classifier regression: " << total << "/" << total
		<< " matched manual labels; hotpatch false positives: 0\n";
	return 0;
}
