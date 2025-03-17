package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Utility to copy data.js around
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer sourceFile.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy contents: %w", err)
	}
	err = destFile.Sync()
	if err != nil {
		return fmt.Errorf("failed to flush contents to destination file: %w", err)
	}
	return nil
}

// listDirectories finds subdirs in data/individual_benchmarks
func listDirectories(inputDir string) ([]string, error) {
	var directories []string
	files, err := os.ReadDir(inputDir)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		if file.IsDir() {
			directories = append(directories, file.Name())
		}
	}
	return directories, nil
}
