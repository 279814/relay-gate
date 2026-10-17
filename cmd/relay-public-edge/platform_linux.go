//go:build linux

package main

import (
	"errors"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

func lockState(directory string) (func(), error) {
	if !filepath.IsAbs(directory) {
		return nil, errors.New("public state directory must be absolute")
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(filepath.Join(directory, "public-edge.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, errors.New("another public edge owns this state directory")
	}
	return func() { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN); _ = file.Close() }, nil
}

func renewalSignals() (<-chan struct{}, func()) {
	signals := make(chan os.Signal, 1)
	trigger := make(chan struct{}, 1)
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGUSR1)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-signals:
				select {
				case trigger <- struct{}{}:
				default:
				}
			}
		}
	}()
	return trigger, func() { signal.Stop(signals); close(done) }
}
