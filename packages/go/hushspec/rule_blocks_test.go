package hushspec

import (
	"sort"
	"strings"
	"testing"
)

// The rule-block names appear in four hand-maintained lists that serve
// different jobs and cannot be one list: the raw validator's walk order, the
// evaluator's block index, the condition walk over the typed `Rules`, and the
// closed `rule_block` enum of a receipt. Each has to hold exactly the twelve
// keys of `rules`, which the generated contract spells once in [RuleKeys], so
// every list is checked against it rather than against another copy.

func ruleKeyNames() []string {
	names := make([]string, 0, len(RuleKeys))
	for name := range RuleKeys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func assertIsRuleKeySet(t *testing.T, label string, names []string) {
	t.Helper()
	got := append([]string(nil), names...)
	sort.Strings(got)
	want := ruleKeyNames()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("%s is %v, want the keys of `rules`: %v", label, got, want)
	}
}

func TestRawConditionBlocksAreTheRuleKeys(t *testing.T) {
	assertIsRuleKeySet(t, "rawConditionBlocks", rawConditionBlocks)
}

func TestBlockNamesAreTheRuleKeys(t *testing.T) {
	assertIsRuleKeySet(t, "blockNames", blockNames[:])
}

func TestRuleConditionsWalksEveryRuleKey(t *testing.T) {
	when := &Condition{Context: map[string]any{"environment": "production"}}
	rules := &Rules{
		ForbiddenPaths:        &ForbiddenPathsRule{When: when},
		PathAllowlist:         &PathAllowlistRule{When: when},
		Egress:                &EgressRule{When: when},
		SecretPatterns:        &SecretPatternsRule{When: when},
		PatchIntegrity:        &PatchIntegrityRule{When: when},
		ShellCommands:         &ShellCommandsRule{When: when},
		ToolAccess:            &ToolAccessRule{When: when},
		ComputerUse:           &ComputerUseRule{When: when},
		RemoteDesktopChannels: &RemoteDesktopChannelsRule{When: when},
		InputInjection:        &InputInjectionRule{When: when},
		BrowserAutomation:     &BrowserAutomationRule{When: when},
		CodeExecution:         &CodeExecutionRule{When: when},
	}
	blocks := ruleConditions(rules)
	names := make([]string, 0, len(blocks))
	for _, block := range blocks {
		names = append(names, block.name)
	}
	assertIsRuleKeySet(t, "ruleConditions", names)
}

func TestReceiptRuleBlocksOpenWithTheRuleKeys(t *testing.T) {
	// The enum is the twelve rule-block ids followed by the engine stages of
	// receipt spec 4.3 item 5, so only the leading run is a rule-block list.
	if len(ReceiptRuleBlocks) < len(RuleKeys) {
		t.Fatalf("ReceiptRuleBlocks holds %d entries, fewer than the %d keys of `rules`",
			len(ReceiptRuleBlocks), len(RuleKeys))
	}
	assertIsRuleKeySet(t, "ReceiptRuleBlocks", ReceiptRuleBlocks[:len(RuleKeys)])
	for _, stage := range ReceiptRuleBlocks[len(RuleKeys):] {
		if _, isRuleKey := RuleKeys[stage]; isRuleKey {
			t.Errorf("ReceiptRuleBlocks lists the rule block %q after the engine stages", stage)
		}
	}
}
