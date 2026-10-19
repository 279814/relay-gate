package protocol

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func TestPayloadSinkIsOptInAndOnlySeesCompleteBoundedObjects(t *testing.T) {
	spec := DecoderSpec{Endpoint: model.EndpointMessages, Protocol: model.ProtoAnthropic}
	var payloads []string
	with, err := NewDecoderWithPayloadSink(spec, WireSSE, 256, 1024, func(v PayloadView) {
		var obj map[string]json.RawMessage = v.Object
		if len(obj) == 0 {
			t.Fatal("sink received an unparsed object")
		}
		payloads = append(payloads, string(v.Raw))
	})
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := NewDecoder(spec, WireSSE, 256, 1024)
	wire := []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n")
	for i, chunk := range [][]byte{wire[:24], wire[24 : len(wire)-1], wire[len(wire)-1:]} {
		a, ea := with.Feed(chunk)
		b, eb := plain.Feed(chunk)
		if !reflect.DeepEqual(a, b) || !reflect.DeepEqual(ea, eb) {
			t.Fatalf("opt-in altered health events: %v %v / %v %v", a, ea, b, eb)
		}
		if i < 2 && len(payloads) != 0 {
			t.Fatal("partial event leaked to sink")
		}
	}
	if len(payloads) != 1 {
		t.Fatalf("payloads=%v", payloads)
	}
	_, _ = with.Finish()
	_, _ = with.Finish()
	if len(payloads) != 1 {
		t.Fatal("Finish repeated payload evidence")
	}
	bounded, _ := NewDecoderWithPayloadSink(spec, WireSSE, 8, 1024, func(PayloadView) { t.Fatal("oversize event reached sink") })
	if _, err := bounded.Feed(wire); err == nil {
		t.Fatal("oversize event accepted")
	}
}
