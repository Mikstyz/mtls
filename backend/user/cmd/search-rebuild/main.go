package main

import (
	"fmt"
	_ "github.com/lib/pq"
	"mtls/shared/searchrebuild"
	"os"
)

func main() {
	if err := searchrebuild.Run("user"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
