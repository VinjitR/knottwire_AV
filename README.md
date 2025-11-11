Go-based signature scanner for files and directories. It reads JSON Lines (JSONL) signature definitions and reports matches, with optional quarantine and export features.

### Features
- Scan files using simple pattern-based signatures
- List last scan results
- Quarantine matched items and restore by ID
- Update signatures from disk
- Export results to JSON

### Requirements
- Go 1.20+

### Build

```bash
go build -o knottwire
```

### Usage

```bash
# Scan a file or directory
knottwire scan <path>

# List last scan results
knottwire list

# Quarantine last results
knottwire quarantine

# Restore a quarantined file by ID
knottwire restore <quarantine_id>

# Reload signatures from disk
knottwire update-signatures

# Export last results to a file
knottwire export-results <file>
```

### Signatures
- Directory: `signatures/`
- File: `signatures/signatures.jsonl`
- Format: one JSON object per line:

```json
{"name":"ExampleSig","type":"pattern","pattern":"malware_sample","description":"Matches 'malware_sample' string"}
```

### Quarantine
- Directory: `quarantine/`
- Metadata: `quarantine/meta.json`

### Notes
- This tool is a Go-based signature scanner and uses string containment for pattern matching in its current form.