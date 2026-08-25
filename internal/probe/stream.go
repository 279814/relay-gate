package probe

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/279814/relay-gate/internal/model"
)

// WireFormat 是响应正文的线协议格式。
type WireFormat string

const (
	WireAuto   WireFormat = "auto"
	WireSSE    WireFormat = "sse"
	WireNDJSON WireFormat = "ndjson"
	WireJSON   WireFormat = "json"
)

// EventKind 是协议事件的粗粒度类别。它只描述观察到的 wire 事实，
// 不决定健康状态或重试动作。
type EventKind string

const (
	EventMetadata    EventKind = "metadata"
	EventSemantic    EventKind = "semantic"
	EventUsage       EventKind = "usage"
	EventModelList   EventKind = "model_list"
	EventProtocolEnd EventKind = "protocol_end"
	EventRemoteError EventKind = "remote_error"
	EventKeepalive   EventKind = "keepalive"
)

// ProtocolEvent 是 Decoder 对一次协议事件的脱敏摘要。
//
// 不保存原始 data 或 error.message：需要原文时由 Sample 旁路按权限保存。
type ProtocolEvent struct {
	Kind                EventKind
	EventName           string
	Semantic            bool
	SemanticKind        string
	OutputTokens        int64
	InputTokens         int64
	ModelListRecognized bool
	ModelCount          int
	ErrorCode           string
	ErrorStatus         int
	RedactedType        string
	ErrorField          string
}

// DecoderSpec 选择协议语义。models 不借用任何 Route Protocol。
type DecoderSpec struct {
	Endpoint model.EndpointKind
	Protocol model.Protocol
}

// Decoder 接收任意网络 chunk，并产出已经完整的 ProtocolEvent。
type Decoder interface {
	Feed(chunk []byte) ([]ProtocolEvent, error)
	Finish() ([]ProtocolEvent, error)
	BytesSeen() int64
}

var (
	ErrInvalidDecoderSpec = errors.New("invalid decoder spec")
	ErrUnknownWireFormat  = errors.New("unknown wire format")
	ErrMalformedWire      = errors.New("malformed wire format")
	ErrIncompleteWire     = errors.New("incomplete wire format")
	ErrTrailingJSON       = errors.New("trailing JSON bytes")
	ErrEventTooLarge      = errors.New("protocol event exceeds limit")
	ErrDecoderWorkBudget  = errors.New("decoder work budget exceeded")
)

type decoderError struct {
	base      error
	format    WireFormat
	offset    int64
	eventType string
	length    int64
	limit     int64
}

func (e *decoderError) Error() string {
	var b strings.Builder
	b.WriteString(e.base.Error())
	if e.format != "" {
		b.WriteString(" format=")
		b.WriteString(string(e.format))
	}
	if e.offset >= 0 {
		b.WriteString(" offset=")
		b.WriteString(strconv.FormatInt(e.offset, 10))
	}
	if e.eventType != "" {
		b.WriteString(" event=")
		b.WriteString(e.eventType)
	}
	if e.length > 0 {
		b.WriteString(" length=")
		b.WriteString(strconv.FormatInt(e.length, 10))
	}
	if e.limit > 0 {
		b.WriteString(" limit=")
		b.WriteString(strconv.FormatInt(e.limit, 10))
	}
	return b.String()
}

func (e *decoderError) Unwrap() error { return e.base }

func makeDecoderError(base error, format WireFormat, offset int64, eventType string, length, limit int64) error {
	return &decoderError{base: base, format: format, offset: offset,
		eventType: eventType, length: length, limit: limit}
}

const defaultDecoderWorkMultiplier = int64(32)

type incrementalDecoder struct {
	spec   DecoderSpec
	format WireFormat

	maxEventBytes int64
	maxTotalBytes int64
	maxWorkUnits  int64
	workUnits     int64
	bytesSeen     int64
	offset        int64

	prefix     []byte
	prefixDone bool
	finished   bool
	terminal   error

	// finishEvents 缓存 Finish 的产出。Finish 要可重复调用并返回同一结果：
	// 调用方（P0-09 的 Executor 与真实流量观察器）会在 readErr 分支上再兜一次，
	// 第二次拿到空序列就等于「EOF 前那个未闭合事件」被静默丢掉。
	finishEvents []ProtocolEvent

	// pending 是 WireAuto 尚未定型时攒下的字节。
	pending []byte

	// jsonBody 只用于普通 JSON；SSE/NDJSON 只保留当前事件或当前行。
	jsonBody []byte

	sseEvent string
	sseData  []byte
	sseLine  []byte

	ndjsonLine []byte
}

// NewDecoder 创建一个增量 Decoder。所有协议组合在读 body 前校验。
func NewDecoder(spec DecoderSpec, format WireFormat, maxEventBytes, maxTotalBytes int64) (Decoder, error) {
	if err := validateDecoderSpec(spec); err != nil {
		return nil, err
	}
	if format != WireAuto && format != WireSSE && format != WireNDJSON && format != WireJSON {
		return nil, makeDecoderError(ErrUnknownWireFormat, format, 0, "", 0, 0)
	}
	if maxEventBytes <= 0 {
		maxEventBytes = 256 << 10
	}
	if maxTotalBytes <= 0 {
		maxTotalBytes = 1 << 20
	}
	return &incrementalDecoder{
		spec:          spec,
		format:        format,
		maxEventBytes: maxEventBytes,
		maxTotalBytes: maxTotalBytes,
		maxWorkUnits:  maxTotalBytes * defaultDecoderWorkMultiplier,
		prefix:        make([]byte, 0, 3),
	}, nil
}

func validateDecoderSpec(spec DecoderSpec) error {
	want := map[model.EndpointKind]model.Protocol{
		model.EndpointMessages:        model.ProtoAnthropic,
		model.EndpointResponses:       model.ProtoOpenAIResponses,
		model.EndpointChatCompletions: model.ProtoOpenAIChat,
		model.EndpointCountTokens:     model.ProtoAnthropic,
	}
	if spec.Endpoint == model.EndpointModels {
		if spec.Protocol != "" {
			return fmt.Errorf("%w: models requires empty protocol", ErrInvalidDecoderSpec)
		}
		return nil
	}
	protocol, ok := want[spec.Endpoint]
	if !ok || spec.Protocol != protocol {
		return fmt.Errorf("%w: endpoint=%s protocol=%s", ErrInvalidDecoderSpec,
			spec.Endpoint, spec.Protocol)
	}
	return nil
}

// DetectWireFormat 使用正文前缀兜底，避免错误或缺失 Content-Type 破坏解析。
//
// 正文形状优先于 Content-Type：公益站常把流式响应标成 application/json，
// 也有的干脆不带头。反过来让声明覆盖实际字节的话，一个形状完全正常的
// SSE 流会被当成畸形 JSON，而症状是「这个站的响应解析不了」——
// 与真正的协议错误无法区分。
//
// JSON 与 NDJSON 的区别只能看「第一个完整值之后还有没有东西」：两者都以
// `{` 开头。仅凭首字符判定会把 NDJSON 锁成 JSON，于是第二行变成尾随字节，
// 报出来的是 ErrTrailingJSON —— 一个把「多行协议」误诊成「上游发了垃圾」
// 的错误。prefix 不完整时返回 WireAuto，让调用方攒够再判。
func DetectWireFormat(contentType string, prefix []byte) WireFormat {
	p := bytes.TrimSpace(bytes.TrimPrefix(prefix, []byte{0xef, 0xbb, 0xbf}))
	lower := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if bytes.HasPrefix(p, []byte("event:")) || bytes.HasPrefix(p, []byte("data:")) ||
		bytes.HasPrefix(p, []byte(":")) || bytes.HasPrefix(p, []byte("[DONE]")) {
		return WireSSE
	}
	if lower == "text/event-stream" {
		return WireSSE
	}
	if lower == "application/x-ndjson" || lower == "application/ndjson" {
		return WireNDJSON
	}
	if bytes.HasPrefix(p, []byte("{")) || bytes.HasPrefix(p, []byte("[")) {
		switch jsonValueShape(p) {
		case shapeSingleValue:
			return WireJSON
		case shapeMultipleValues:
			return WireNDJSON
		default:
			return WireAuto
		}
	}
	return WireAuto
}

type jsonShape int

const (
	shapeIncomplete jsonShape = iota
	shapeSingleValue
	shapeMultipleValues
)

// jsonValueShape 回答「这段字节是一个完整 JSON 值，还是后面还跟着别的值」。
func jsonValueShape(body []byte) jsonShape {
	reader := bytes.NewReader(body)
	decoder := json.NewDecoder(reader)
	var first json.RawMessage
	if err := decoder.Decode(&first); err != nil {
		// 值还没收完（跨 chunk）与真正的语法错误在这里不区分：两种都还不能定型，
		// 交给调用方继续攒或在 EOF 时报错。
		return shapeIncomplete
	}
	buffered, _ := io.ReadAll(decoder.Buffered())
	tail, _ := io.ReadAll(reader)
	if len(bytes.TrimSpace(append(buffered, tail...))) > 0 {
		return shapeMultipleValues
	}
	return shapeSingleValue
}

func (d *incrementalDecoder) BytesSeen() int64 { return d.bytesSeen }

func (d *incrementalDecoder) Feed(chunk []byte) ([]ProtocolEvent, error) {
	if d.finished {
		return nil, d.terminal
	}
	if d.terminal != nil {
		return nil, d.terminal
	}
	if len(chunk) == 0 {
		return nil, nil
	}
	if int64(len(chunk)) > d.maxTotalBytes-d.bytesSeen {
		return nil, d.fail(makeDecoderError(ErrDecodedBodyTooLarge, d.effectiveFormat(), d.offset, "", d.bytesSeen+int64(len(chunk)), d.maxTotalBytes))
	}
	d.bytesSeen += int64(len(chunk))
	if int64(len(chunk)) > d.maxWorkUnits-d.workUnits {
		return nil, d.fail(makeDecoderError(ErrDecoderWorkBudget, d.effectiveFormat(), d.offset, "", d.workUnits+int64(len(chunk)), d.maxWorkUnits))
	}
	d.workUnits += int64(len(chunk))

	payload, ready := d.consumePrefix(chunk)
	if !ready {
		return nil, nil
	}
	if d.format == WireAuto {
		// 未定型：先攒着。只看当前 chunk 不行 —— 逐字节到达时每次只有 1 字节，
		// 而 NDJSON 与 JSON 的区别在第一个完整值之后才出现。
		if int64(len(d.pending)+len(payload)) > d.maxEventBytes {
			return nil, d.fail(makeDecoderError(ErrUnknownWireFormat, WireAuto, d.offset,
				"", int64(len(d.pending)+len(payload)), d.maxEventBytes))
		}
		d.pending = append(d.pending, payload...)
		format := DetectWireFormat("", d.pending)
		// WireJSON 的定型推迟到 Finish：此刻「一个完整值且没有尾随」只说明
		// 到目前为止如此，下一个 chunk 可能带来第二行 —— 那就是 NDJSON。
		// 提前定成 JSON 的话，第二行会被当成尾随垃圾报 ErrTrailingJSON。
		if format == WireAuto || format == WireJSON {
			return nil, nil
		}
		d.format = format
		payload = d.pending
		d.pending = nil
	}
	return d.feedPayload(payload)
}

// consumePrefix 只负责剥掉一次开头的 UTF-8 BOM。
//
// 攒够 3 字节才能判定，但攒不够时**不能**把字节吞掉：`{}` 这类短正文
// 一辈子等不到第 3 个字节，那样 Finish 就会拿到一个空 body 并报 incomplete。
// 所以 Finish 走 flushPrefix 把攒下的原样交出来。
func (d *incrementalDecoder) consumePrefix(chunk []byte) ([]byte, bool) {
	if d.prefixDone {
		return chunk, true
	}
	d.prefix = append(d.prefix, chunk...)
	if len(d.prefix) < 3 {
		return nil, false
	}
	return d.flushPrefix(), true
}

// flushPrefix 把攒下的前缀交出去，并剥掉 BOM。
func (d *incrementalDecoder) flushPrefix() []byte {
	d.prefixDone = true
	payload := d.prefix
	d.prefix = nil
	return bytes.TrimPrefix(payload, []byte{0xef, 0xbb, 0xbf})
}

func (d *incrementalDecoder) feedPayload(payload []byte) ([]ProtocolEvent, error) {
	switch d.format {
	case WireSSE:
		return d.feedSSE(payload)
	case WireNDJSON:
		return d.feedNDJSON(payload)
	case WireJSON:
		if int64(len(d.jsonBody)+len(payload)) > d.maxTotalBytes {
			return nil, d.fail(makeDecoderError(ErrDecodedBodyTooLarge, d.format, d.offset, "", int64(len(d.jsonBody)+len(payload)), d.maxTotalBytes))
		}
		d.jsonBody = append(d.jsonBody, payload...)
		return nil, nil
	default:
		return nil, d.fail(makeDecoderError(ErrUnknownWireFormat, d.format, d.offset, "", 0, 0))
	}
}

func (d *incrementalDecoder) feedSSE(payload []byte) ([]ProtocolEvent, error) {
	d.sseLine = append(d.sseLine, payload...)
	var events []ProtocolEvent
	for {
		index := bytes.IndexByte(d.sseLine, '\n')
		if index < 0 {
			if int64(len(d.sseLine)+len(d.sseData)) > d.maxEventBytes {
				return events, d.fail(makeDecoderError(ErrEventTooLarge, d.format, d.offset, d.sseEvent, int64(len(d.sseLine)+len(d.sseData)), d.maxEventBytes))
			}
			return events, nil
		}
		line := d.sseLine[:index]
		d.sseLine = d.sseLine[index+1:]
		d.offset += int64(index + 1)
		line = bytes.TrimSuffix(line, []byte{'\r'})
		if len(line) == 0 {
			got, err := d.commitSSE()
			if err != nil {
				return events, d.fail(err)
			}
			events = append(events, got...)
			continue
		}
		if line[0] == ':' {
			continue
		}
		name, value := splitSSEField(line)
		switch name {
		case "event":
			d.sseEvent = string(value)
		case "data":
			if int64(len(d.sseData)+len(value)+1) > d.maxEventBytes {
				return events, d.fail(makeDecoderError(ErrEventTooLarge, d.format, d.offset, d.sseEvent, int64(len(d.sseData)+len(value)+1), d.maxEventBytes))
			}
			if len(d.sseData) > 0 {
				d.sseData = append(d.sseData, '\n')
			}
			d.sseData = append(d.sseData, value...)
		}
	}
}

func splitSSEField(line []byte) (string, []byte) {
	index := bytes.IndexByte(line, ':')
	if index < 0 {
		return string(line), nil
	}
	value := line[index+1:]
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return string(line[:index]), value
}

func (d *incrementalDecoder) commitSSE() ([]ProtocolEvent, error) {
	name := d.sseEvent
	if len(d.sseData) == 0 {
		// 没有 data 行的事件仍然是一个事件（§8.8 的「无 data」）：很多站的
		// keepalive 只发 `event: ping` 加空行。丢掉它会让「站在吐心跳」与
		// 「站一个字节都没回」在上层看起来一样，而这两种要给用户的提示相反。
		d.sseEvent = ""
		if name == "" {
			return nil, nil
		}
		return d.decodeEventName(name)
	}
	data := append([]byte(nil), d.sseData...)
	d.sseEvent = ""
	d.sseData = d.sseData[:0]
	if bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
		return []ProtocolEvent{{Kind: EventProtocolEnd, EventName: "done"}}, nil
	}
	return d.decodePayload(name, data)
}

// decodeEventName 处理只有 event 行、没有 data 的 SSE 事件。
func (d *incrementalDecoder) decodeEventName(name string) ([]ProtocolEvent, error) {
	switch name {
	case "ping":
		return []ProtocolEvent{{Kind: EventKeepalive, EventName: name}}, nil
	case "done", "[DONE]":
		return []ProtocolEvent{{Kind: EventProtocolEnd, EventName: "done"}}, nil
	default:
		return []ProtocolEvent{{Kind: EventMetadata, EventName: name}}, nil
	}
}

func (d *incrementalDecoder) feedNDJSON(payload []byte) ([]ProtocolEvent, error) {
	d.ndjsonLine = append(d.ndjsonLine, payload...)
	var events []ProtocolEvent
	for {
		index := bytes.IndexByte(d.ndjsonLine, '\n')
		if index < 0 {
			if int64(len(d.ndjsonLine)) > d.maxEventBytes {
				return events, d.fail(makeDecoderError(ErrEventTooLarge, d.format, d.offset, "", int64(len(d.ndjsonLine)), d.maxEventBytes))
			}
			return events, nil
		}
		line := bytes.TrimSpace(bytes.TrimSuffix(d.ndjsonLine[:index], []byte{'\r'}))
		d.ndjsonLine = d.ndjsonLine[index+1:]
		d.offset += int64(index + 1)
		if len(line) == 0 {
			continue
		}
		got, err := d.decodePayload("", line)
		if err != nil {
			return events, d.fail(err)
		}
		events = append(events, got...)
	}
}

func (d *incrementalDecoder) Finish() ([]ProtocolEvent, error) {
	if d.finished {
		// 同一份结果，不是空序列 —— 见 finishEvents 的说明。
		return d.finishEvents, d.terminal
	}
	d.finished = true
	if d.terminal != nil {
		return nil, d.terminal
	}

	// 不足 3 字节就到了 EOF：把攒下的前缀交给 parser，否则短正文会整份丢失。
	if !d.prefixDone {
		payload := d.flushPrefix()
		if d.format == WireAuto {
			d.pending = append(d.pending, payload...)
		} else if _, err := d.feedPayload(payload); err != nil {
			d.terminal = err
			return nil, d.terminal
		}
	}

	// WireAuto 到 EOF 仍未定型：此时已经看到全部字节，用完整正文再判一次。
	// 逐字节喂入时前缀探测每次只拿到 1 字节，NDJSON 的第二行要到这里才出现。
	if d.format == WireAuto {
		d.format = DetectWireFormat("", d.pending)
		if d.format == WireAuto {
			d.terminal = makeDecoderError(ErrUnknownWireFormat, WireAuto, d.offset, "", int64(len(d.pending)), 0)
			return nil, d.terminal
		}
		pending := d.pending
		d.pending = nil
		if _, err := d.feedPayload(pending); err != nil {
			d.terminal = err
			return nil, d.terminal
		}
	}

	events, err := d.finishFormat()
	if err != nil {
		d.terminal = d.fail(err)
		return nil, d.terminal
	}
	d.finishEvents = events
	return events, nil
}

func (d *incrementalDecoder) finishFormat() ([]ProtocolEvent, error) {
	switch d.format {
	case WireSSE:
		if len(d.sseLine) > 0 {
			line := bytes.TrimSuffix(d.sseLine, []byte{'\r'})
			d.sseLine = nil
			if len(line) > 0 && line[0] != ':' {
				name, value := splitSSEField(line)
				switch name {
				case "event":
					d.sseEvent = string(value)
				case "data":
					if len(d.sseData) > 0 {
						d.sseData = append(d.sseData, '\n')
					}
					d.sseData = append(d.sseData, value...)
				}
			}
		}
		return d.commitSSE()
	case WireNDJSON:
		if len(bytes.TrimSpace(d.ndjsonLine)) > 0 {
			return nil, makeDecoderError(ErrIncompleteWire, d.format, d.offset,
				"", int64(len(d.ndjsonLine)), d.maxEventBytes)
		}
		return nil, nil
	case WireJSON:
		return d.finishJSON()
	default:
		return nil, makeDecoderError(ErrUnknownWireFormat, d.effectiveFormat(), d.offset, "", 0, 0)
	}
}

func (d *incrementalDecoder) finishJSON() ([]ProtocolEvent, error) {
	body := bytes.TrimSpace(d.jsonBody)
	if len(body) == 0 {
		return nil, makeDecoderError(ErrIncompleteWire, WireJSON, d.offset, "", 0, 0)
	}
	if !utf8.Valid(body) {
		return nil, makeDecoderError(ErrMalformedWire, WireJSON, d.offset, "", int64(len(body)), 0)
	}
	reader := bytes.NewReader(body)
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, makeDecoderError(ErrMalformedWire, WireJSON, d.offset, "", int64(len(body)), 0)
	}
	remaining, _ := io.ReadAll(decoder.Buffered())
	tail, _ := io.ReadAll(reader)
	remaining = append(remaining, tail...)
	if len(bytes.TrimSpace(remaining)) > 0 {
		return nil, makeDecoderError(ErrTrailingJSON, WireJSON, int64(len(body)-len(remaining)), "", int64(len(remaining)), 0)
	}
	return d.decodePayload("", raw)
}

func (d *incrementalDecoder) decodePayload(eventName string, payload []byte) ([]ProtocolEvent, error) {
	if int64(len(payload)) > d.maxEventBytes {
		return nil, makeDecoderError(ErrEventTooLarge, d.format, d.offset, eventName, int64(len(payload)), d.maxEventBytes)
	}
	if !utf8.Valid(payload) {
		return nil, makeDecoderError(ErrMalformedWire, d.format, d.offset, eventName, int64(len(payload)), 0)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(payload, &object); err != nil {
		if d.spec.Endpoint == model.EndpointModels && d.spec.Protocol == "" {
			var list []json.RawMessage
			if arrayErr := json.Unmarshal(payload, &list); arrayErr == nil {
				return []ProtocolEvent{{Kind: EventModelList, EventName: "model_list", Semantic: true,
					ModelListRecognized: true, ModelCount: len(list)}}, nil
			}
		}
		return nil, makeDecoderError(ErrMalformedWire, d.format, d.offset, eventName, int64(len(payload)), 0)
	}
	return d.eventFromObject(eventName, object, payload)
}

func (d *incrementalDecoder) eventFromObject(eventName string, object map[string]json.RawMessage, payload []byte) ([]ProtocolEvent, error) {
	if raw, ok := object["error"]; ok && !bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return []ProtocolEvent{remoteErrorEvent(eventName, raw)}, nil
	}
	if d.spec.Endpoint == model.EndpointModels {
		if raw, ok := object["data"]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) == nil {
				return []ProtocolEvent{{Kind: EventModelList, EventName: "model_list", Semantic: true,
					ModelListRecognized: true, ModelCount: len(list)}}, nil
			}
		}
		return []ProtocolEvent{{Kind: EventMetadata, EventName: eventName}}, nil
	}
	if d.spec.Endpoint == model.EndpointCountTokens {
		value, ok := integerField(object, "input_tokens")
		if ok && value > 0 {
			return []ProtocolEvent{{Kind: EventSemantic, EventName: "count_tokens", Semantic: true,
				InputTokens: value}}, nil
		}
		return []ProtocolEvent{{Kind: EventMetadata, EventName: "count_tokens"}}, nil
	}

	name := eventName
	if value := stringField(object, "type"); value != "" {
		name = value
	}
	if name == "" && d.spec.Protocol == model.ProtoOpenAIChat {
		if d.format == WireJSON {
			name = "chat.completion"
		} else {
			name = "chat.completion.chunk"
		}
	}
	// `{"type":"error","code":...}` —— 错误直接长在事件上，没有嵌套的 error 对象。
	// 只认嵌套形态的话，这种事件会变成一条普通 metadata，于是 200 流内错误
	// 在上层看起来跟「站还在正常吐事件」一样。
	if name == "error" {
		return []ProtocolEvent{remoteErrorEvent(name, payload)}, nil
	}
	if name == "ping" {
		return []ProtocolEvent{{Kind: EventKeepalive, EventName: name}}, nil
	}
	if name == "[DONE]" || name == "done" {
		return []ProtocolEvent{{Kind: EventProtocolEnd, EventName: "done"}}, nil
	}

	event := ProtocolEvent{Kind: EventMetadata, EventName: name}
	switch d.spec.Protocol {
	case model.ProtoAnthropic:
		classifyAnthropic(&event, name, object)
	case model.ProtoOpenAIResponses:
		classifyResponses(&event, name, object)
	case model.ProtoOpenAIChat:
		classifyChat(&event, name, object)
	}
	if event.Semantic {
		event.Kind = EventSemantic
	} else if event.OutputTokens > 0 {
		event.Kind = EventUsage
	}
	_ = payload
	return []ProtocolEvent{event}, nil
}

func classifyAnthropic(event *ProtocolEvent, name string, object map[string]json.RawMessage) {
	if name == "message_delta" {
		if usage, ok := object["usage"]; ok {
			var value map[string]json.RawMessage
			if json.Unmarshal(usage, &value) == nil {
				// 只记数，不设 Semantic：token 数不是内容证据（§8.8）。
				event.OutputTokens, _ = integerField(value, "output_tokens")
			}
		}
		return
	}
	if name != "content_block_delta" {
		return
	}
	var delta map[string]json.RawMessage
	if json.Unmarshal(object["delta"], &delta) != nil {
		return
	}
	deltaType := stringField(delta, "type")
	var field string
	switch deltaType {
	case "text_delta":
		field = "text"
		event.SemanticKind = "text"
	case "thinking_delta":
		field = "thinking"
		event.SemanticKind = "thinking"
	case "input_json_delta":
		field = "partial_json"
		event.SemanticKind = "input_json"
	case "tool_use_delta":
		field = "partial_json"
		event.SemanticKind = "tool"
	}
	if field != "" && nonEmptyString(delta[field]) {
		event.Semantic = true
	}
}

func classifyResponses(event *ProtocolEvent, name string, object map[string]json.RawMessage) {
	fields := map[string]string{
		"response.output_text.delta":             "text",
		"response.reasoning_summary_text.delta":  "reasoning",
		"response.refusal.delta":                 "refusal",
		"response.function_call_arguments.delta": "function_args",
	}
	if semanticKind, ok := fields[name]; ok {
		if nonEmptyString(object["delta"]) {
			event.Semantic = true
			event.SemanticKind = semanticKind
		}
	}
	if name == "response.completed" {
		if response, ok := object["response"]; ok {
			var body map[string]json.RawMessage
			if json.Unmarshal(response, &body) == nil {
				if usage, ok := body["usage"]; ok {
					var values map[string]json.RawMessage
					if json.Unmarshal(usage, &values) == nil {
						event.OutputTokens, _ = integerField(values, "output_tokens")
					}
				}
			}
		}
	}
}

func classifyChat(event *ProtocolEvent, name string, object map[string]json.RawMessage) {
	if name == "" {
		if _, ok := object["choices"]; ok {
			name = "chat.completion"
			event.EventName = name
		}
	}
	var choices []map[string]json.RawMessage
	if raw, ok := object["choices"]; ok {
		_ = json.Unmarshal(raw, &choices)
	}
	for _, choice := range choices {
		var delta map[string]json.RawMessage
		if raw, ok := choice["delta"]; ok {
			_ = json.Unmarshal(raw, &delta)
		}
		var message map[string]json.RawMessage
		if raw, ok := choice["message"]; ok {
			_ = json.Unmarshal(raw, &message)
		}
		for field, kind := range map[string]string{
			"content": "text", "reasoning_content": "reasoning", "refusal": "refusal",
		} {
			value := delta[field]
			if len(value) == 0 {
				value = message[field]
			}
			if nonEmptyString(value) {
				event.Semantic = true
				event.SemanticKind = kind
				break
			}
		}
		if raw, ok := delta["tool_calls"]; ok && bytes.Contains(raw, []byte("arguments")) {
			event.Semantic = true
			event.SemanticKind = "tool"
		}
		if raw, ok := delta["function_call"]; ok && bytes.Contains(raw, []byte("arguments")) {
			event.Semantic = true
			event.SemanticKind = "function_args"
		}
	}
	if usage, ok := object["usage"]; ok {
		var values map[string]json.RawMessage
		if json.Unmarshal(usage, &values) == nil {
			event.OutputTokens, _ = integerField(values, "completion_tokens")
			if event.OutputTokens == 0 {
				event.OutputTokens, _ = integerField(values, "output_tokens")
			}
		}
	}
	if name == "done" {
		event.Kind = EventProtocolEnd
		event.Semantic = false
	}
}

func remoteErrorEvent(eventName string, raw json.RawMessage) ProtocolEvent {
	if eventName == "" {
		eventName = "error"
	}
	event := ProtocolEvent{Kind: EventRemoteError, EventName: eventName}
	var body map[string]json.RawMessage
	if json.Unmarshal(raw, &body) != nil {
		event.RedactedType = "error"
		return event
	}
	event.RedactedType = stringField(body, "type")
	event.ErrorCode = scalarString(body["code"])
	status, ok := integerField(body, "status")
	if ok {
		event.ErrorStatus = int(status)
	}
	event.ErrorField = stringField(body, "param")
	return event
}

func stringField(object map[string]json.RawMessage, name string) string {
	value, ok := object[name]
	if !ok {
		return ""
	}
	var result string
	if json.Unmarshal(value, &result) == nil {
		return result
	}
	return ""
}

func scalarString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var result string
	if json.Unmarshal(raw, &result) == nil {
		return result
	}
	var number json.Number
	if json.Unmarshal(raw, &number) == nil {
		return number.String()
	}
	return ""
}

func integerField(object map[string]json.RawMessage, name string) (int64, bool) {
	raw, ok := object[name]
	if !ok {
		return 0, false
	}
	var number json.Number
	if err := json.Unmarshal(raw, &number); err != nil {
		return 0, false
	}
	value, err := number.Int64()
	return value, err == nil
}

func nonEmptyString(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value != ""
}

func (d *incrementalDecoder) effectiveFormat() WireFormat {
	if d.format == "" {
		return WireAuto
	}
	return d.format
}

func (d *incrementalDecoder) fail(err error) error {
	if d.terminal == nil {
		d.terminal = err
	}
	return d.terminal
}
