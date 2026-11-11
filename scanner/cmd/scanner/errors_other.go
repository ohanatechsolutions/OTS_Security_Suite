//go:build !windows

package main

import (
	"fmt"
	"os"
)

func showErrorDialog(message string) { fmt.Fprintln(os.Stderr, message) }
