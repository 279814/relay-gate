// relay-public-edge owns Certbot and Nginx only. It cannot read gateway keys,
// sample bodies or SQLite, and never participates in forwarding admission.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/279814/relay-gate/internal/acmeip"
)

func run(args []string, out, diagnostic io.Writer) error {
	flags := flag.NewFlagSet("relay-public-edge", flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	ip := flags.String("ip", os.Getenv("RELAY_PUBLIC_IP"), "confirmed public IPv4 or IPv6")
	confirmed := flags.String("confirmed-ip", os.Getenv("RELAY_CONFIRMED_PUBLIC_IP"), "explicit target confirmation; must equal --ip")
	stateDir := flags.String("state-dir", "/state", "private persistent ACME/TLS directory")
	webroot := flags.String("webroot", "/webroot", "public HTTP-01 directory")
	upstream := flags.String("upstream", "http://172.30.187.3:18787", "fixed internal gateway address")
	checkIP := flags.Bool("check-ip", false, "validate and print canonical public IP; never starts ACME")
	status := flags.Bool("status", false, "print persisted public metadata; never starts ACME")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *status {
		state, err := acmeip.ReadPublicState(filepath.Join(*stateDir, "status", "state.json"))
		if err != nil {
			return fmt.Errorf("HTTPS state unavailable: %w", err)
		}
		return json.NewEncoder(out).Encode(state)
	}
	address, err := acmeip.ParsePublicIP(*ip)
	if err != nil {
		return err
	}
	if *checkIP {
		_, err = fmt.Fprintln(out, address.String())
		return err
	}
	confirmation, err := acmeip.ParsePublicIP(*confirmed)
	if err != nil || confirmation != address {
		return fmt.Errorf("public IP requires explicit matching --confirmed-ip")
	}
	unlock, err := lockState(*stateDir)
	if err != nil {
		return err
	}
	defer unlock()
	trigger, stopRenewSignals := renewalSignals()
	defer stopRenewSignals()
	manager, err := acmeip.NewPublicManager(acmeip.PublicOptions{
		IP: address.String(), StateDir: *stateDir, Webroot: *webroot, Upstream: *upstream,
		Output: diagnostic, RenewTrigger: trigger,
	})
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return manager.Run(ctx)
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "public HTTPS:", err)
		os.Exit(1)
	}
}
