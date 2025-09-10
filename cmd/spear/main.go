package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/sammwyy/spear/core"
)

func main() {
	var configPath = flag.String("config", "/etc/spear/config.toml", "Path to configuration file")
	var version = flag.Bool("version", false, "Show version information")
	var help = flag.Bool("help", false, "Show help information")

	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *version {
		showVersion()
		return
	}

	// Create and start daemon
	daemon, err := core.NewDaemon(*configPath)
	if err != nil {
		log.Fatalf("Failed to create daemon: %v", err)
	}

	if err := daemon.Start(); err != nil {
		log.Fatalf("Daemon failed: %v", err)
	}
}

func showHelp() {
	fmt.Println("Spear HIDS/NIDS Daemon")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  spear [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -config string    Path to configuration file (default \"/etc/spear/config.toml\")")
	fmt.Println("  -version          Show version information")
	fmt.Println("  -help             Show this help message")
	fmt.Println()
	fmt.Println("For more information, visit: https://github.com/sammwyy/spear")
}

func showVersion() {
	fmt.Println("Spear HIDS/NIDS")
	fmt.Println("Version: 1.0.0")
	fmt.Println("Repository: https://github.com/sammwyy/spear")
}
