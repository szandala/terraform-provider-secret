package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteFile_TightensExistingPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	path := filepath.Join(t.TempDir(), "prod.env")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	// WriteFile is subject to umask on creation only; force the loose mode.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := writeFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	if b, _ := os.ReadFile(path); string(b) != "secret" {
		t.Fatalf("content = %q, want %q", b, "secret")
	}
}

// The cases below never reach the interactive prompt, so they are safe to run
// with or without a terminal.
func TestConfirmOverwrite_Force(t *testing.T) {
	path := filepath.Join(t.TempDir(), "prod.env")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := confirmOverwrite(path, "", true); err != nil {
		t.Fatalf("--force must not ask or fail, got %v", err)
	}
	// confirmOverwrite only decides; it must not touch the file itself.
	if b, _ := os.ReadFile(path); string(b) != "precious" {
		t.Fatalf("file changed: %q", b)
	}
}

func TestConfirmOverwrite_NoQuestionNeeded(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing")
	if err := os.WriteFile(existing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct{ out, in string }{
		"no --out":            {"", ""},
		"stdout":              {"-", ""},
		"file does not exist": {filepath.Join(dir, "new"), ""},
		"directory":           {dir, ""},
		"in-place (out==in)":  {existing, existing},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if err := confirmOverwrite(c.out, c.in, false); err != nil {
				t.Fatalf("got %v, want nil", err)
			}
		})
	}
}

func TestWriteFile_NewFileAndNoLoosening(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	dir := t.TempDir()

	fresh := filepath.Join(dir, "fresh")
	if err := writeFile(fresh, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o600 {
		t.Fatalf("new file mode = %o, want 600", fi.Mode().Perm())
	}

	// A stricter existing file must not be widened by a 0644 write (ciphertext).
	strict := filepath.Join(dir, "strict")
	if err := os.WriteFile(strict, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(strict, []byte("AES256;..."), 0o644); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(strict); fi.Mode().Perm() != 0o600 {
		t.Fatalf("existing 0600 file widened to %o", fi.Mode().Perm())
	}
}
