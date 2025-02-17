package util

import (
	"golang.org/x/term"
	"os"
	"path/filepath"
)

func LoadTemplate(path, file, builtin string) (string, error) {
	file = filepath.Join(path, file)
	if !FileExists(file) {
		return builtin, nil
	}

	content, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func FileExists(file string) bool {
	_, err := os.Stat(file)
	return err == nil
}

func InteractiveTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}
