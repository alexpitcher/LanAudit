package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/alexpitcher/LanAudit/internal/tui"
)

var (
	headless = flag.Bool("headless", false, "Run in headless mode (JSON output)")
	iface    = flag.String("iface", "", "Network interface to use")
	snap     = flag.Bool("snap", false, "Create snapshot and exit")
	version  = flag.Bool("version", false, "Print version and exit")
)

const Version = "0.1.0-mvp"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("LanAudit %s\n", Version)
		os.Exit(0)
	}

	ctx := context.Background()

	if *headless {
		if *iface == "" {
			fmt.Fprintf(os.Stderr, "Error: --iface required in headless mode\n")
			os.Exit(1)
		}

		if err := tui.RunHeadless(ctx, *iface); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *iface != "" {
		if err := tui.RunWithInterface(*iface); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Default: run TUI
	if err := tui.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
