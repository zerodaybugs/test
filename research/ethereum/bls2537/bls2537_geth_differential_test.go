package vm

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestBLS2537SharedCorpus executes the same deterministic EIP-2537 corpus as the Besu runner.
// Results are normalized to OK:<hex> or ERR so implementation-specific error strings cannot mask
// a consensus acceptance/output discrepancy.
func TestBLS2537SharedCorpus(t *testing.T) {
	corpusPath := requiredBLS2537Environment(t, "BLS2537_CORPUS_FILE")
	resultPath := requiredBLS2537Environment(t, "BLS2537_RESULT_FILE")

	operations := map[string]PrecompiledContract{
		"G1ADD":      &bls12381G1Add{},
		"G1MSM":      &bls12381G1MultiExp{},
		"G2ADD":      &bls12381G2Add{},
		"G2MSM":      &bls12381G2MultiExp{},
		"PAIRING":    &bls12381Pairing{},
		"MAP_FP_G1":  &bls12381MapG1{},
		"MAP_FP2_G2": &bls12381MapG2{},
	}

	corpus, err := os.Open(corpusPath)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer corpus.Close()

	output, err := os.Create(resultPath)
	if err != nil {
		t.Fatalf("create result: %v", err)
	}
	writer := bufio.NewWriter(output)
	defer func() {
		if err := writer.Flush(); err != nil {
			t.Errorf("flush result: %v", err)
		}
		if err := output.Close(); err != nil {
			t.Errorf("close result: %v", err)
		}
	}()

	scanner := bufio.NewScanner(corpus)
	scanner.Buffer(make([]byte, 4096), 2<<20)
	count := 0
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		if len(fields) != 3 {
			t.Fatal("BLS2537_INVALID_CORPUS_ROW")
		}
		operation := operations[fields[1]]
		if operation == nil {
			t.Fatal("BLS2537_UNKNOWN_OPERATION")
		}
		input, err := hex.DecodeString(fields[2])
		if err != nil {
			t.Fatal("BLS2537_INVALID_HEX")
		}
		result, runErr := operation.Run(input)
		normalized := "ERR"
		if runErr == nil {
			normalized = "OK:" + hex.EncodeToString(result)
		}
		if _, err := fmt.Fprintf(writer, "%s\t%s\t%s\n", fields[0], fields[1], normalized); err != nil {
			t.Fatalf("write result: %v", err)
		}
		count++
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	t.Logf("BLS2537_GETH_COMPLETE cases=%d", count)
}

func requiredBLS2537Environment(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("BLS2537_MISSING_ENVIRONMENT_%s", key)
	}
	return value
}
