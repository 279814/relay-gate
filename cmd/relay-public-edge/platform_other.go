//go:build !linux

package main

import "errors"

func lockState(string) (func(), error) {
	return nil, errors.New("public HTTPS runs in the Linux edge container")
}
func renewalSignals() (<-chan struct{}, func()) { return nil, func() {} }
