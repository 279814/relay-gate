//go:build !windows

package main

import "os"

func cliCheckPrivatePermissions(_ string, info os.FileInfo) error {
	if info.Mode().Perm()&0077 != 0 {
		return errCLIPrivateInput
	}
	return nil
}

func cliPathIsReparse(string) bool { return false }

func cliRestrictPrivatePath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0600)
	if info.IsDir() {
		mode = 0700
	}
	return os.Chmod(path, mode)
}
