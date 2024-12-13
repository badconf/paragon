# Paragon
A Go tool for comparing hundreds of files and analyzing their differences. It allows comparing files either by their SHA-256 hash or through a line-by-line content analysis.

## Features

- SHA-256 hash file analysis
- Detailed line-by-line content comparison
- Support for different file types (configurable extension)
- Secure input/output handling
- Protection against malicious paths
- Configurable security limits

## Prerequisites

- Go 1.16 or higher
- No external dependencies (uses only Go standard library)

## Installation

```bash
# Clone the repository
git clone https://github.com/badconf/paragon.git

# Go to the directory
cd paragon

# Build the program
go build -o paragon
```

## Usage

The program accepts three command-line parameters:

- `-p`: Path to the directory to analyze (required)
- `-t`: Type of analysis to perform (required)
  - `hash`: Compare files by their SHA-256 hash, export a brut csv result file
  - `content`: Compare content line by line
- `-f`: Extension of files to analyze (optional, default: txt)

### Usage Examples

```bash
# Compare txt files by hash
./paragon -p /path/to/directory -t hash

# Compare csv files content
./paragon -p /path/to/directory -t content -f csv

# Use default extension (txt)
./paragon -p /path/to/directory -t hash
```

### Output Examples

#### Hash Analysis

```
Hash analysis results:
Total number of txt files analyzed: 5
Number of different hashes: 2

Hash: a1b2c3d4e5f6g7h8...
Number of files: 3

Hash: h8g7f6e5d4c3b2a1...
Number of files: 2
```

#### Content Analysis

```
Analysis of differences compared to reference file (txt):
Reference file: file1.txt

Different file: file2.txt
  → Different lines: [3, 4, 10]

  Difference details:
    Line 3:
      Reference : Reference line content
      Different : Different line content
```

## Limits and Constraints

- Maximum file size: 100MB
- Maximum line size: 1MB
- Maximum number of differences displayed: 1000
- Maximum number of files analyzed: 10000

## Security

The program includes several security mechanisms:

- Path validation to prevent path traversal
- File permissions verification
- Limits on file and line sizes
- User input validation

## Customization

The following constants can be modified in the source code to adjust the limits:

```go
const (
    maxFileSize     = 100 * 1024 * 1024 // 100MB
    maxLineSize     = 1024 * 1024       // 1MB
    maxDifferences  = 1000
    maxFilesToCheck = 10000
)
```

## License

This project is under the GPL License. See the [GPL-3.0](LICENSE) file for more details.
