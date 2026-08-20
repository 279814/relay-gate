package store

import (
	"errors"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestPageCursorBindsResourceFilterAndStableKeys(t *testing.T) {
	filter := model.EndpointFilter{UpstreamID: 7, Endpoint: model.EndpointMessages}
	cursor, err := encodePageCursor("endpoint", filter, "42", "messages")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := decodePageCursor(cursor, "endpoint", filter, 2)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"42", "messages"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys = %#v, want %#v", keys, want)
	}
	if _, err := decodePageCursor(cursor, "recipe", filter, 2); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("cross-resource cursor error = %v", err)
	}
	changed := filter
	changed.UpstreamID++
	if _, err := decodePageCursor(cursor, "endpoint", changed, 2); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("changed-filter cursor error = %v", err)
	}
	if _, err := decodePageCursor(cursor, "endpoint", filter, 1); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("wrong key count error = %v", err)
	}
	if _, err := decodePageCursor("not-base64", "endpoint", filter, 2); !errors.Is(err, ErrInvalidCursor) {
		t.Fatalf("malformed cursor error = %v", err)
	}
}

func TestNormalizePageLimitDefaultsAndCaps(t *testing.T) {
	tests := []struct {
		input   int
		want    int
		wantErr bool
	}{
		{0, 50, false},
		{1, 1, false},
		{200, 200, false},
		{-1, 0, true},
		{201, 0, true},
	}
	for _, tc := range tests {
		got, err := normalizePageLimit(tc.input)
		if got != tc.want || (err != nil) != tc.wantErr {
			t.Errorf("normalizePageLimit(%d) = %d,%v want %d,err=%v", tc.input, got, err, tc.want, tc.wantErr)
		}
		if err != nil && !errors.Is(err, ErrInvalidCursor) {
			t.Errorf("limit error = %v, want ErrInvalidCursor", err)
		}
	}
}
