package model

import "errors"

const (
	ClientProfileScopeLimit    = 8
	ClientProfileUpstreamLimit = 64
	ClientProfileGlobalLimit   = 2048
)

var ErrClientProfileCapacity = errors.New("client profile candidate capacity reached")
