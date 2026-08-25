package probe

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/279814/relay-gate/internal/model"
)

func fixtureDecoderSpec(t *testing.T, fixture fixtureCase) DecoderSpec {
	t.Helper()
	var endpoint model.EndpointKind
	var protocol model.Protocol
	switch fixture.Endpoint {
	case "models":
		endpoint = model.EndpointModels
	case "messages":
		endpoint, protocol = model.EndpointMessages, model.ProtoAnthropic
	case "responses":
		endpoint, protocol = model.EndpointResponses, model.ProtoOpenAIResponses
	case "chat_completions":
		endpoint, protocol = model.EndpointChatCompletions, model.ProtoOpenAIChat
	case "count_tokens":
		endpoint, protocol = model.EndpointCountTokens, model.ProtoAnthropic
	default:
		t.Fatalf("fixture %q has unknown endpoint %q", fixture.ID, fixture.Endpoint)
	}
	return DecoderSpec{Endpoint: endpoint, Protocol: protocol}
}

func decodeFixture(t *testing.T, fixture fixtureCase, chunks [][]byte) ([]ProtocolEvent, error) {
	t.Helper()
	format := WireFormat(fixture.WireFormat)
	decoder, err := NewDecoder(fixtureDecoderSpec(t, fixture), format, 256<<10, 1<<20)
	if err != nil {
		return nil, err
	}
	var events []ProtocolEvent
	for _, chunk := range chunks {
		got, err := decoder.Feed(chunk)
		if err != nil {
			return events, err
		}
		events = append(events, got...)
	}
	got, err := decoder.Finish()
	events = append(events, got...)
	return events, err
}

func fixtureEventSummary(events []ProtocolEvent) [][3]string {
	result := make([][3]string, 0, len(events))
	for _, event := range events {
		result = append(result, [3]string{
			event.EventName,
			fmt.Sprintf("%t", event.Semantic),
			fmt.Sprintf("%t", event.Kind == EventRemoteError),
		})
	}
	return result
}

func expectedFixtureEventSummary(events []fixtureEvent) [][3]string {
	result := make([][3]string, 0, len(events))
	for _, event := range events {
		result = append(result, [3]string{event.Type,
			fmt.Sprintf("%t", event.Semantic), fmt.Sprintf("%t", event.Error)})
	}
	return result
}

func expectedEventsAppearInOrder(actual [][3]string, want [][3]string) bool {
	index := 0
	for _, event := range actual {
		if index < len(want) && event == want[index] {
			index++
		}
	}
	return index == len(want)
}
func TestDecoderManifestFixturesProduceExpectedEventsAcrossChunkPlans(t *testing.T) {
	manifest, err := loadFixtureManifest("testdata")
	if err != nil {
		t.Fatalf("load fixture manifest: %v", err)
	}

	for _, fixture := range manifest.Cases {
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join("testdata", filepath.FromSlash(fixture.ResponseFile)))
			if err != nil {
				t.Fatal(err)
			}
			wire, chunks, err := splitFixtureResponse(body, fixture.ChunkPlan)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeFixture(t, fixture, chunks)
			if err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			want := expectedFixtureEventSummary(fixture.ExpectedEvents)
			if !expectedEventsAppearInOrder(fixtureEventSummary(got), want) {
				t.Fatalf("expected events are not an ordered subsequence: actual=%#v want=%#v", fixtureEventSummary(got), want)
			}

			_, wholeChunks, err := splitFixtureResponse(body, fixtureChunkPlan{Name: "whole"})
			if err != nil {
				t.Fatal(err)
			}
			whole, err := decodeFixture(t, fixture, wholeChunks)
			if err != nil {
				t.Fatalf("decode whole fixture: %v", err)
			}
			if !reflect.DeepEqual(fixtureEventSummary(got), fixtureEventSummary(whole)) {
				t.Fatalf("chunk plan changed events: planned=%#v whole=%#v", fixtureEventSummary(got), fixtureEventSummary(whole))
			}
			if !bytes.Equal(bytes.Join(chunks, nil), wire) {
				t.Fatal("fixture chunks do not reconstruct wire")
			}
		})
	}
}
