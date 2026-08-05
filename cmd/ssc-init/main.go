package main

import (
	"context"
	"os"

	"github.com/ssc-init/ssc-init/internal/cli"
)

func main() {
	os.Exit(cli.Run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}
