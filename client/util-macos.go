//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	anchor = "rst_filter" // PF anchor name (correctly defined here)
)

func applyFilteringRules(srcAddr, dstAddr net.IP, srcPort, dstPort int) error {
	// 1. Check if PF is enabled
	if enabled, err := isPFEnabled(); err != nil || !enabled {
		fmt.Printf("PF service is not enabled: %v\n", err)
		os.Exit(1)
	}

	// 2. Dynamically manage the anchor
	if err := pfManageAnchor(anchor, true); err != nil {
		fmt.Printf("Failed to initialize anchor: %v\n", err)
		os.Exit(1)
	}
	defer pfManageAnchor(anchor, false) // Ensure anchor is removed on exit

	// 3. Clear old rules
	if err := pfFlushRules(anchor); err != nil {
		fmt.Printf("Failed to clear old rules: %v\n", err)
		os.Exit(1)
	}

	// 4. Construct precise rule (with logging)
	rule := fmt.Sprintf(
		"block drop out inet proto tcp "+
			"from %s port = %d to %s port = %d flags R/R\n",
		srcAddr.String(), srcPort, dstAddr.String(), dstPort,
	)
	fmt.Println("Constructed rule:", rule)

	// 5. Add rule
	if err := pfLoadRules(anchor, rule); err != nil {
		fmt.Printf("Failed to add rule: %v\n", err)
		os.Exit(1)
	}

	// 6. Strictly verify rule
	if err := verifyRuleExactMatch(anchor, rule); err != nil {
		fmt.Printf("Rule verification failed: %v\n", err)
		os.Exit(1)
	}

	// 7. Keep running
	fmt.Printf("Successfully loaded rule:\n%s\nWaiting for Ctrl+C to exit...\n", strings.TrimSpace(rule))

	return nil
}

func removeFilteringRules() error {
	return pfFlushRules(anchor)
}

// ================= PF Control Functions =================
func isPFEnabled() (bool, error) {
	output, err := exec.Command("pfctl", "-s", "info").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("macos PFctl check failed: %v\nOutput: %s", err, string(output))
	}
	return strings.Contains(string(output), "Status: Enabled"), nil
}

func pfManageAnchor(anchor string, create bool) error {
	action := "anchor"
	if !create {
		action = "no anchor"
	}
	cmd := exec.Command("pfctl", "-a", ".", "-f", "-")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("%s \"%s\"\n", action, anchor))
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("macos pf anchor operation failed: %v\nCommand output: %s", err, string(output))
	}
	return nil
}

func pfFlushRules(anchor string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-F", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to clear macos pf rules: %v\nOutput: %s", err, string(output))
	}
	return nil
}

func pfLoadRules(anchor, rules string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to load macos pf rules: %v\nCommand output: %s", err, string(output))
	}
	return nil
}

// ================= Verification Functions =================
func verifyRuleExactMatch(anchor, expectedRule string) error {
	cmd := exec.Command("pfctl", "-a", anchor, "-s", "rules")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to query macos pf rules: %v", err)
	}

	// Strictly match the rule (including line breaks)
	expected := strings.TrimSpace(expectedRule)
	current := strings.TrimSpace(string(output))
	if !strings.Contains(current, expected) {
		return fmt.Errorf("rule does not match\nmacos pf current rules:\n%s\nExpected rule:\n%s",
			current, expected)
	}
	return nil
}

func isAdmin() bool {
	return os.Getuid() == 0
}
