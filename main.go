package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	APP_NAME = "KnottWire"
	VERSION  = "1.0.0"
	AUTHOR   = "KnottWire"
)

const (
	signatureDir   = "signatures"
	signatureFile  = "signatures.jsonl"
	quarantineDir  = "quarantine"
	quarantineMeta = "meta.json"
)

// Signature defines a malware signature
type Signature struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

// ScanResult holds the result of a scan
type ScanResult struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	Hash           string    `json:"hash"`
	Signature      Signature `json:"signature"`
	Severity       string    `json:"severity"`
	Description    string    `json:"description"`
	FilePath       string    `json:"file_path"`
	NeedUserAction bool      `json:"need_user_action"`
}

// QuarantineItem stores metadata about quarantined files
type QuarantineItem struct {
	ID                 string    `json:"id"`
	Timestamp          time.Time `json:"timestamp"`
	Hash               string    `json:"hash"`
	Description        string    `json:"description"`
	DetectedBy         string    `json:"detected_by"`
	OriginalFilePath   string    `json:"original_file_path"`
	QuarantineFilePath string    `json:"quarantine_file_path"`
}

var (
	signatures  []Signature
	lastResults []ScanResult
	resultLock  sync.Mutex
)

// main is the entry point that routes CLI commands
func main() {
	fmt.Printf("🚀 Starting %s v%s by %s\n", APP_NAME, VERSION, AUTHOR)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	cmd := os.Args[1]

	ensureQuarantineDir()

	if err := loadSignatures(); err != nil {
		fmt.Println("❌ Error loading signatures:", err)
		os.Exit(1)
	}

	switch cmd {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: knottwire scan <file/directory>")
			os.Exit(1)
		}
		path := os.Args[2]
		results, err := scanFile(path, signatures)
		if err != nil {
			fmt.Println("Error scanning file:", err)
			os.Exit(1)
		}
		resultLock.Lock()
		lastResults = results
		resultLock.Unlock()

		fmt.Println("🧪 Scan results:", len(results))
		for _, result := range results {
			fmt.Printf("- %s | %s | %s | Action Required: %v\n",
				result.Signature.Name, result.Description, result.FilePath, result.NeedUserAction)
		}

	case "list":
		listResults()

	case "quarantine":
		resultLock.Lock()
		_, err := quarantineResults(lastResults)
		resultLock.Unlock()
		if err != nil {
			fmt.Println("Error quarantining files:", err)
			os.Exit(1)
		}

	case "restore":
		if len(os.Args) < 3 {
			fmt.Println("Usage: knottwire restore <quarantine_id>")
			os.Exit(1)
		}
		restoreFromQuarantine(os.Args[2])

	case "update-signatures":
		updateSignatures()

	case "export-results":
		if len(os.Args) < 3 {
			fmt.Println("Usage: knottwire export-results <file>")
			os.Exit(1)
		}
		exportResults(os.Args[2])

	default:
		usage()
		os.Exit(1)
	}
}

// scanFile simulates scanning a file and returns dummy results
func scanFile(path string, signatures []Signature) ([]ScanResult, error) {
	fmt.Println("🔍 Scanning file:", path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	lines := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	var results []ScanResult
	for _, sig := range signatures {
		if sig.Pattern != "" {
			for _, line := range lines {
				if strings.Contains(line, sig.Pattern) {
					results = append(results, ScanResult{
						ID:             fmt.Sprintf("%d", time.Now().UnixNano()),
						Timestamp:      time.Now(),
						Hash:           "dummyhash",
						Signature:      sig,
						Severity:       "medium",
						Description:    sig.Description,
						FilePath:       path,
						NeedUserAction: true,
					})
					continue
				}
			}
		}
	}
	return results, nil
}

// listResults prints the last scan results
func listResults() {
	resultLock.Lock()
	defer resultLock.Unlock()
	if len(lastResults) == 0 {
		fmt.Println("No scan results available.")
		return
	}
	for _, r := range lastResults {
		fmt.Printf("- %s | %s | %s | %s\n", r.ID, r.Signature.Name, r.FilePath, r.Description)
	}
}

// quarantineResults moves infected files to quarantine and saves metadata
func quarantineResults(results []ScanResult) ([]QuarantineItem, error) {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Failed to get current directory:", err)
		return nil, err
	}
	fmt.Println("🔒 Quarantining results...")
	var quarantined []QuarantineItem
	for _, r := range results {
		item := QuarantineItem{
			ID:                 r.ID,
			Timestamp:          r.Timestamp,
			Hash:               r.Hash,
			Description:        r.Description,
			DetectedBy:         r.Signature.Name,
			OriginalFilePath:   r.FilePath,
			QuarantineFilePath: filepath.Join(currentDir, quarantineDir, r.ID+".quarantine"),
		}
		_ = os.WriteFile(item.QuarantineFilePath, []byte(r.Description), 0600)
		quarantined = append(quarantined, item)
	}

	data, err := json.MarshalIndent(quarantined, "", "  ")
	if err != nil {
		return nil, err
	}
	err = os.WriteFile(quarantineMeta, data, 0600)
	if err != nil {
		return nil, err
	}

	fmt.Println("✅ Quarantined:", len(quarantined))
	for _, q := range quarantined {
		fmt.Printf("- %s | %s | %s\n", q.ID, q.Timestamp.Format(time.RFC3339), q.Description)
	}
	return quarantined, nil
}

// restoreFromQuarantine restores a file from quarantine by ID
func restoreFromQuarantine(id string) {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Failed to get current directory:", err)
		return
	}
	path := filepath.Join(currentDir, quarantineDir, id+".quarantine")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		fmt.Println("❌ Quarantine file not found:", path)
		return
	}
	restorePath := filepath.Join(currentDir, "restored_"+id)
	err = os.Rename(path, restorePath)
	if err != nil {
		fmt.Println("❌ Failed to restore file:", err)
		return
	}
	fmt.Println("✅ Restored to:", restorePath)
}

// updateSignatures reloads the signature file
func updateSignatures() {
	if err := loadSignatures(); err != nil {
		fmt.Println("❌ Failed to update signatures:", err)
	} else {
		fmt.Println("✅ Signatures updated.")
	}
}

// exportResults writes the last scan results to a file
func exportResults(filename string) {
	resultLock.Lock()
	defer resultLock.Unlock()
	data, err := json.MarshalIndent(lastResults, "", "  ")
	if err != nil {
		fmt.Println("❌ Failed to export results:", err)
		return
	}
	err = os.WriteFile(filename, data, 0644)
	if err != nil {
		fmt.Println("❌ Failed to write results:", err)
	} else {
		fmt.Println("📁 Results exported to", filename)
	}
}

// loadSignatures loads malware signatures from JSON
func loadSignatures() error {
	currentDir, err := os.Getwd()
	if err != nil {
		return err
	}
	signaturePath := filepath.Join(currentDir, signatureDir, signatureFile)
	file, err := os.Open(signaturePath)
	fmt.Println("🔍 Loading signatures from:", signaturePath)
	if err != nil {
		return err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var signature Signature
		err := json.Unmarshal([]byte(scanner.Text()), &signature)
		if err != nil {
			return err
		}
		signatures = append(signatures, signature)
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

// ensureQuarantineDir creates quarantine directory and metadata file if missing
func ensureQuarantineDir() {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println("❌ Failed to get current directory:", err)
		return
	}
	if _, err := os.Stat(filepath.Join(currentDir, quarantineDir)); os.IsNotExist(err) {
		_ = os.MkdirAll(filepath.Join(currentDir, quarantineDir), 0700)
	}
	if _, err := os.Stat(filepath.Join(currentDir, quarantineDir, quarantineMeta)); os.IsNotExist(err) {
		_ = os.WriteFile(filepath.Join(currentDir, quarantineDir, quarantineMeta), []byte("[]"), 0600)
	}
}

// usage prints help text
func usage() {
	fmt.Println("Usage:")
	fmt.Println("  knottwire <command> [options]")
	fmt.Println("Commands:")
	fmt.Println("  scan <file/directory>")
	fmt.Println("  list")
	fmt.Println("  quarantine")
	fmt.Println("  restore <quarantine_id>")
	fmt.Println("  update-signatures")
	fmt.Println("  export-results <file>")
	fmt.Println("\nExamples:")
	fmt.Println("  knottwire scan /path/to/file.exe")
	fmt.Println("  knottwire list")
	fmt.Println("  knottwire quarantine")
	fmt.Println("  knottwire restore 1234567890")
	fmt.Println("  knottwire update-signatures")
	fmt.Println("  knottwire export-results results.json")
}
