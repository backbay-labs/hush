// Controlled faulty engine used only by the controller's black-box tests.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

func main() {
	raw, _ := io.ReadAll(os.Stdin)
	var request map[string]json.RawMessage
	if err := json.Unmarshal(raw, &request); err != nil {
		panic(err)
	}
	mode := os.Args[1]
	switch mode {
	case "hang":
		time.Sleep(30 * time.Second)
	case "exit":
		os.Exit(7)
	case "signal":
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
		time.Sleep(time.Second)
	case "stdout":
		fmt.Print(strings.Repeat("x", 2*1024*1024))
		return
	case "stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 2*1024*1024))
		return
	case "malformed":
		fmt.Print("not JSON")
		return
	case "replace_original", "replace_fixture":
		if err := os.WriteFile(os.Args[2], []byte("changed after capture"), 0600); err != nil {
			panic(err)
		}
	}
	result := map[string]any{"status": "ok", "value": map[string]any{"hushspec": "1.0.0"}}
	var operation string
	_ = json.Unmarshal(request["operation"], &operation)
	var input map[string]any
	_ = json.Unmarshal(request["input"], &input)
	if operation == "resolve" || operation == "canonicalize" {
		result = map[string]any{"status": "unsupported"}
	}
	if operation == "evaluate" {
		result = map[string]any{"status": "ok", "value": map[string]any{"decision": "allow"}}
	}
	if mode == "honest" && strings.Contains(fmt.Sprint(input["policy"]), "unknown:") {
		result = map[string]any{"status": "rejected", "phase": "parse", "code": "E001", "diagnostic": "unknown field"}
	}
	if mode == "unsupported" {
		result = map[string]any{"status": "unsupported"}
	}
	if mode == "error" {
		result = map[string]any{"status": "error", "diagnostic": "unrelated internal error"}
	}
	response := map[string]any{"result": result}
	for _, key := range []string{"protocol", "run_id", "case_id", "operation", "input_sha256"} {
		response[key] = request[key]
	}
	switch mode {
	case "stale":
		response["run_id"] = "old-run"
	case "wrong_case":
		response["case_id"] = "foreign-case"
	case "wrong_operation":
		response["operation"] = "merge"
	case "wrong_digest":
		response["input_sha256"] = strings.Repeat("a", 64)
	case "missing":
		delete(response, "case_id")
	}
	encoded, _ := json.Marshal(response)
	if mode == "duplicate" {
		encoded = append([]byte(`{"run_id":"duplicate",`), encoded[1:]...)
	}
	_, _ = os.Stdout.Write(encoded)
	if mode == "multiple" {
		_, _ = os.Stdout.Write(encoded)
	}
}
