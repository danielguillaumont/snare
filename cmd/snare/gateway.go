package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/danielguillaumont/snare/internal/gateway"
)

// gatewayCmd runs the Snare gateway in front of a real MCP server (docs/M6-gateway.md):
//
//	snare gateway -config gw.json -- npx some-mcp-server --its-flags
func gatewayCmd(args []string) error {
	if len(args) > 0 && args[0] == "pins" {
		return gatewayPins(args[1:], os.Stdout)
	}
	if len(args) > 0 && args[0] == "release" {
		return gatewayRelease(args[1:])
	}
	fs := flag.NewFlagSet("gateway", flag.ExitOnError)
	config := fs.String("config", "", "gateway config written by snare plant gateway")
	verbose := fs.Bool("v", false, "log gateway activity to stderr (never tool arguments)")
	_ = fs.Parse(args)
	server := fs.Args() // flag parsing stops at "--" and drops it
	if *config == "" || len(server) == 0 {
		fs.Usage()
		return errors.New("usage: snare gateway -config F -- <real server command> [args]")
	}
	cfg, err := gateway.LoadConfig(*config)
	if err != nil {
		return err
	}
	level := slog.LevelWarn
	if *verbose {
		level = slog.LevelInfo
	}
	// stdout is the MCP channel; everything else goes to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	child := exec.Command(server[0], server[1:]...)
	child.Stderr = os.Stderr
	in, err := child.StdinPipe()
	if err != nil {
		return err
	}
	out, err := child.StdoutPipe()
	if err != nil {
		return err
	}
	if err := child.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", server[0], err)
	}
	g := &gateway.Gateway{Cfg: cfg, Log: log}
	runErr := g.Run(context.Background(), os.Stdin, os.Stdout, in, out)
	waitErr := child.Wait()
	var exit *exec.ExitError
	if errors.As(waitErr, &exit) {
		os.Exit(exit.ExitCode()) // the client sees the real server's exit status
	}
	if runErr != nil {
		return runErr
	}
	return waitErr
}
