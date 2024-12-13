package main

import (
	"bufio"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxFileSize     = 100 * 1024 * 1024 // 100MB
	maxLineSize     = 1024 * 1024       // 1MB
	maxDifferences  = 1000              // Maximum differences to store
	maxFilesToCheck = 10000             // Maximum files to analyze
)

type HashCount struct {
	hash  string
	count int
	files []string
}

type LineDifference struct {
	lineNumber  int
	refContent  string
	diffContent string
}

type FileDifference struct {
	filename     string
	differences  []LineDifference
	isLengthDiff bool
	truncated    bool
}

type FileAnalyzer struct {
	directory  string
	fileExt    string
	reference  string
	files      []string
	hashCounts map[string]*HashCount
}

type Config struct {
	directory    string
	analysisType string
	fileExt      string
}

func parseFlags() (*Config, error) {
	var config Config

	flag.StringVar(&config.directory, "p", "", "Path to the directory to analyze")
	flag.StringVar(&config.analysisType, "t", "", "Analysis type (hash or content)")
	flag.StringVar(&config.fileExt, "f", "txt", "File extension to analyze (without the dot)")

	flag.Parse()

	// Validate mandatory parameters
	if config.directory == "" {
		return nil, fmt.Errorf("parameter -p (directory path) is mandatory")
	}
	if config.analysisType == "" {
		return nil, fmt.Errorf("parameter -t (analysis type) is mandatory")
	}
	if config.analysisType != "hash" && config.analysisType != "content" {
		return nil, fmt.Errorf("invalid analysis type. Use 'hash' or 'content'")
	}

	// Clean the extension
	config.fileExt = strings.TrimPrefix(config.fileExt, ".")

	return &config, nil
}

func isValidPath(path string) error {
	if !filepath.IsAbs(path) {
		absPath, err := filepath.Abs(path)
		if err != nil {
			return fmt.Errorf("unable to resolve absolute path: %v", err)
		}
		path = absPath
	}

	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("unable to access path: %v", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("path is not a directory")
	}

	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("unauthorized path: contains '..'")
	}

	return nil
}

func isValidFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("unable to access file: %v", err)
	}

	if info.Size() > maxFileSize {
		return fmt.Errorf("file too large: %s (%d bytes)", path, info.Size())
	}

	if info.Mode().Perm()&0004 == 0 {
		return fmt.Errorf("insufficient permissions to read file: %s", path)
	}

	return nil
}

func NewFileAnalyzer(config *Config) (*FileAnalyzer, error) {
	if err := isValidPath(config.directory); err != nil {
		return nil, err
	}

	var validFiles []string
	entries, err := os.ReadDir(config.directory)
	if err != nil {
		return nil, fmt.Errorf("error reading directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()),
			"."+strings.ToLower(config.fileExt)) {
			filePath := filepath.Join(config.directory, entry.Name())
			if err := isValidFile(filePath); err != nil {
				log.Printf("Warning: ignored file %s: %v", filePath, err)
				continue
			}
			validFiles = append(validFiles, filePath)
		}
	}

	if len(validFiles) == 0 {
		return nil, fmt.Errorf("no valid %s files found in directory %s",
			config.fileExt, config.directory)
	}

	if len(validFiles) > maxFilesToCheck {
		log.Printf("Warning: limiting to %d files (out of %d found)",
			maxFilesToCheck, len(validFiles))
		validFiles = validFiles[:maxFilesToCheck]
	}

	return &FileAnalyzer{
		directory:  config.directory,
		fileExt:    config.fileExt,
		reference:  validFiles[0],
		files:      validFiles,
		hashCounts: make(map[string]*HashCount),
	}, nil
}

func (fa *FileAnalyzer) calculateHash(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func (fa *FileAnalyzer) analyzeByHash() error {
	for _, file := range fa.files {
		hash, err := fa.calculateHash(file)
		if err != nil {
			return fmt.Errorf("error calculating hash for %s: %v", file, err)
		}

		if count, exists := fa.hashCounts[hash]; exists {
			count.count++
			count.files = append(count.files, filepath.Base(file))
		} else {
			fa.hashCounts[hash] = &HashCount{
				hash:  hash,
				count: 1,
				files: []string{filepath.Base(file)},
			}
		}
	}

	return nil
}

func (fa *FileAnalyzer) printHashAnalysis() {
	fmt.Println("\nHash analysis results:")
	fmt.Printf("Total number of %s files analyzed: %d\n",
		fa.fileExt, len(fa.files))
	fmt.Printf("Number of different hashes: %d\n\n", len(fa.hashCounts))

	var results []HashCount
	for _, count := range fa.hashCounts {
		results = append(results, *count)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].count > results[j].count
	})

	for _, result := range results {
		fmt.Printf("Hash: %s\n", result.hash)
		fmt.Printf("Number of files: %d\n\n", result.count)
	}

	// Write CSV file
	file, err := os.Create("result.csv")
	if err != nil {
		log.Printf("Error creating CSV file: %v", err)
		return
	}
	defer file.Close()

	writer := bufio.NewWriter(file)

	// Write header with UTF-8 BOM for Excel
	writer.WriteString("\uFEFF")
	writer.WriteString("File name;complete hash;number of occurrences\n")

	// For each hash, write a line for each file
	for _, result := range results {
		for _, fileName := range result.files {
			line := fmt.Sprintf("%s;%s;%d\n",
				fileName,
				result.hash,
				result.count)
			writer.WriteString(line)
		}
	}

	if err := writer.Flush(); err != nil {
		log.Printf("Error writing CSV file: %v", err)
		return
	}

	fmt.Printf("The result.csv file has been created successfully.\n")
}

func (fa *FileAnalyzer) compareFileContent(reference, current string) (*FileDifference, error) {
	refFile, err := os.Open(reference)
	if err != nil {
		return nil, err
	}
	defer refFile.Close()

	curFile, err := os.Open(current)
	if err != nil {
		return nil, err
	}
	defer curFile.Close()

	refScanner := bufio.NewScanner(refFile)
	refScanner.Buffer(make([]byte, maxLineSize), maxLineSize)

	curScanner := bufio.NewScanner(curFile)
	curScanner.Buffer(make([]byte, maxLineSize), maxLineSize)

	lineNum := 0
	var differences []LineDifference
	truncated := false

	for refScanner.Scan() {
		lineNum++
		refLine := refScanner.Text()

		if !curScanner.Scan() {
			if err := curScanner.Err(); err != nil {
				if err == bufio.ErrTooLong {
					return nil, fmt.Errorf("line too long in current file (limit: %d bytes)", maxLineSize)
				}
				return nil, fmt.Errorf("error reading current file: %v", err)
			}
			return &FileDifference{
				filename:     filepath.Base(current),
				isLengthDiff: true,
				differences:  differences,
				truncated:    truncated,
			}, nil
		}

		curLine := curScanner.Text()
		if refLine != curLine {
			if len(differences) >= maxDifferences {
				truncated = true
				break
			}
			differences = append(differences, LineDifference{
				lineNumber:  lineNum,
				refContent:  refLine,
				diffContent: curLine,
			})
		}
	}

	if err := refScanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			return nil, fmt.Errorf("line too long in reference file (limit: %d bytes)", maxLineSize)
		}
		return nil, fmt.Errorf("error reading reference file: %v", err)
	}

	if curScanner.Scan() {
		return &FileDifference{
			filename:     filepath.Base(current),
			isLengthDiff: true,
			differences:  differences,
			truncated:    truncated,
		}, nil
	}

	if err := curScanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading current file: %v", err)
	}

	if len(differences) == 0 {
		return nil, nil
	}

	return &FileDifference{
		filename:     filepath.Base(current),
		differences:  differences,
		isLengthDiff: false,
		truncated:    truncated,
	}, nil
}

func (fa *FileAnalyzer) analyzeByContent() error {
	fmt.Printf("\nAnalyzing differences compared to reference file (%s):\n", fa.fileExt)
	fmt.Printf("Reference file: %s\n\n", filepath.Base(fa.reference))

	differentFiles := 0

	for _, file := range fa.files[1:] {
		diff, err := fa.compareFileContent(fa.reference, file)
		if err != nil {
			return fmt.Errorf("error comparing with %s: %v", file, err)
		}

		if diff != nil {
			differentFiles++
			fmt.Printf("Different file: %s\n", diff.filename)
			if diff.isLengthDiff {
				fmt.Println("  → Different number of lines")
			}

			if len(diff.differences) > 0 {
				lineNumbers := make([]int, len(diff.differences))
				for i, d := range diff.differences {
					lineNumbers[i] = d.lineNumber
				}
				fmt.Printf("  → Different lines: %v\n\n", lineNumbers)

				fmt.Println("  Difference details:")
				for _, d := range diff.differences {
					fmt.Printf("    Line %d:\n", d.lineNumber)
					fmt.Printf("      Reference : %s\n", d.refContent)
					fmt.Printf("      Different : %s\n", d.diffContent)
					fmt.Println()
				}

				if diff.truncated {
					fmt.Printf("  ⚠ Warning: display limited to %d differences\n", maxDifferences)
				}
			}
			fmt.Println()
		}
	}

	fmt.Printf("Summary: %d different files out of %d %s files analyzed\n",
		differentFiles, len(fa.files)-1, fa.fileExt)

	return nil
}

func main() {
	// Parse and validate arguments
	config, err := parseFlags()
	if err != nil {
		log.Fatalf("Error in parameters: %v\n\n"+
			"Usage: program -p <directory> -t <analysis-type> [-f <extension>]\n"+
			"Available analysis types:\n"+
			"  hash    - Compare file hashes\n"+
			"  content - List different files with different line contents\n"+
			"Default extension: txt", err)
	}

	// Create analyzer with configuration
	analyzer, err := NewFileAnalyzer(config)
	if err != nil {
		log.Fatal(err)
	}

	// Execute requested analysis
	switch config.analysisType {
	case "hash":
		if err := analyzer.analyzeByHash(); err != nil {
			log.Fatal(err)
		}
		analyzer.printHashAnalysis()

	case "content":
		if err := analyzer.analyzeByContent(); err != nil {
			log.Fatal(err)
		}
	}
}
