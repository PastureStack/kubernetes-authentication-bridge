package main

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestOperatorMessagesIncludeTraditionalChinese(t *testing.T) {
	if got := operatorMessage("en-US", "username"); got != "Username" {
		t.Fatalf("unexpected English operator message: %q", got)
	}
	if got := operatorMessage("zh-TW", "username"); got != "使用者名稱" {
		t.Fatalf("unexpected Traditional Chinese operator message: %q", got)
	}
}

func TestRunPrintsNumericVersion(t *testing.T) {
	oldVersion := VERSION
	VERSION = "0.0.12"
	defer func() { VERSION = oldVersion }()
	var output bytes.Buffer
	if err := run([]string{"--version"}, strings.NewReader(""), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "0.0.12\n" {
		t.Fatalf("unexpected version output %q", output.String())
	}
}

func TestRunEvaluatesTestProvider(t *testing.T) {
	var output bytes.Buffer
	err := run([]string{"--test-authentication", "--evaluate-token=test1", "--locale=zh-TW"}, strings.NewReader(""), &output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "使用者名稱 test1") {
		t.Fatalf("unexpected evaluation output %q", output.String())
	}
}

func TestEnvironmentDurationRejectsInvalidValue(t *testing.T) {
	t.Setenv("PASTURESTACK_BOOTSTRAP_TIMEOUT", "zero")
	if _, err := environmentDuration("PASTURESTACK_BOOTSTRAP_TIMEOUT", time.Minute); err == nil {
		t.Fatal("expected invalid duration to fail")
	}
}

func TestSafeLogValueProducesSingleRecord(t *testing.T) {
	if got := safeLogValue("first\r\nforged\nthird"); got != "first forged third" {
		t.Fatalf("unexpected safe log value: %q", got)
	}
}
