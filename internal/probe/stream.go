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
	ErrDecoderFinished    = errors.New("decoder already finished")
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

// defaultDecoderWorkMultiplier 把工作预算定为「总字节数的若干倍」。
//
// 用工作量而不是 CPU 时间：Go 没有可移植的单 goroutine CPU 时间接口，而基于
// 墙上时钟的预算会让测试与 fuzz 的结果随机器负载漂移。
const defaultDecoderWorkMultiplier = int64(32)

// maxAutoPrefixScan 是 WireAuto 尚无换行时参与格式判定的前缀长度。
//
// 判 SSE/NDJSON/JSON 只看开头那几个字节（`event:`、`data:`、`{`、`[`），
// 扫更多没有额外信息，却会在逐字节到达时把每次重判变成一次全缓冲扫描。
const maxAutoPrefixScan = 64

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
	//
	// pendingScanned/Depth/InString/Escaped 是括号配平的增量状态：只有在配平
	// 时才值得重判格式，而增量维护让「已扫到哪」不必每次从头再数。
	pending         []byte
	pendingScanned  int
	pendingDepth    int
	pendingInString bool
	pendingEscaped  bool

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
		// Finish 之后到达的字节要报错，不能静默丢掉：静默返回空序列的话，
		// 一个把 Finish 提前调用了的调用方会看到「流里什么都没有」，而字节
		// 其实到了、只是被扔了 —— 排查方向从一开始就是错的。
		if d.terminal != nil {
			return nil, d.terminal
		}
		return nil, makeDecoderError(ErrDecoderFinished, d.effectiveFormat(), d.offset, "", 0, 0)
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
	if err := d.spendWork(int64(len(chunk))); err != nil {
		return nil, err
	}

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
		format, err := d.detectPendingFormat()
		if err != nil {
			return nil, err
		}
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

// detectPendingFormat 对已攒下的 pending 重判一次格式，并把重扫成本记进预算。
//
// 重判要扫整个已攒缓冲，所以逐字节到达时它本身是平方复杂度：一份攒到上限的
// 正文能把一次探活变成几十秒的纯 CPU，而探活跑在调度器起的 goroutine 里、
// 每 30 秒一轮、站有几十个。工作预算就是为这个准备的 —— 计入的必须是**扫过的
// 字节数**而不是收到的字节数，否则预算恒等于 maxTotalBytes 的倍数，永远不触发。
//
// 只在「刚刚收尾了一个顶层值」时才重扫。判据是括号已配平：不配平就不可能
// 出现第二个顶层值，NDJSON 与 JSON 还没有分歧，重扫必然得到同一个答案。
// 少了这层短路，缩进过的 JSON（models 列表常常是）会在每个字节上重扫全缓冲，
// 于是一份完全合法的正文撞上预算 —— 症状是「这个站的响应解析不了」，而站是好的。
func (d *incrementalDecoder) detectPendingFormat() (WireFormat, error) {
	if !d.pendingClosedAValue() {
		return DetectWireFormat("", d.pending[:min(len(d.pending), maxAutoPrefixScan)]), nil
	}
	if err := d.spendWork(int64(len(d.pending))); err != nil {
		return WireAuto, err
	}
	return DetectWireFormat("", d.pending), nil
}

// pendingClosedAValue 增量维护括号深度，回答「已攒的字节是否刚好收尾了一个
// 顶层值」。增量是关键：每次重新数一遍就又是平方复杂度。
func (d *incrementalDecoder) pendingClosedAValue() bool {
	for ; d.pendingScanned < len(d.pending); d.pendingScanned++ {
		switch c := d.pending[d.pendingScanned]; {
		case d.pendingInString:
			if d.pendingEscaped {
				d.pendingEscaped = false
			} else if c == '\\' {
				d.pendingEscaped = true
			} else if c == '"' {
				d.pendingInString = false
			}
		case c == '"':
			d.pendingInString = true
		case c == '{' || c == '[':
			d.pendingDepth++
		case c == '}' || c == ']':
			d.pendingDepth--
		}
	}
	return d.pendingDepth <= 0 && !d.pendingInString
}

func (d *incrementalDecoder) spendWork(units int64) error {
	if units > d.maxWorkUnits-d.workUnits {
		return d.fail(makeDecoderError(ErrDecoderWorkBudget, d.effectiveFormat(), d.offset, "",
			d.workUnits+units, d.maxWorkUnits))
	}
	d.workUnits += units
	return nil
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
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, makeDecoderError(ErrMalformedWire, WireJSON, d.offset, "", int64(len(body)), 0)
	}
	// json.Decoder 会为解析首个值**预读**尾随字节，所以只看底层 reader 是不够的：
	// `{...} garbage` 里的 garbage 留在 decoder 自己的缓冲里，尾随检查会静默失效。
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
			if list, isList := decodeJSONArray(payload); isList {
				return []ProtocolEvent{{Kind: EventModelList, EventName: "model_list", Semantic: true,
					ModelListRecognized: true, ModelCount: len(list)}}, nil
			}
		}
		return nil, makeDecoderError(ErrMalformedWire, d.format, d.offset, eventName, int64(len(payload)), 0)
	}
	return d.eventFromObject(eventName, object, payload)
}

// modelListEventName 给 models 端点的事件一个非空名字。
//
// SSE/NDJSON 有自己的事件名就用它；普通 JSON 没有（顶层对象不带 event 行），
// 回落到 model_list。
func modelListEventName(eventName string) string {
	if eventName != "" {
		return eventName
	}
	return "model_list"
}

// decodeJSONArray 解出一个 JSON 数组，并把 null 与「不是数组」一同拒掉。
//
// 必须显式排除 null：`json.Unmarshal([]byte("null"), &slice)` **返回 nil
// error** 并把 slice 置为 nil —— JSON null 对任何 Go 类型都合法。于是
// `{"data":null}` 与 `{"data":[]}`（§4.6 明说合法的空列表）在解析结果上
// 完全相同，而一个回 `{"status":"ok","data":null}` 带 200 的站（后端尚未
// 就绪时的常见形态）会被判成 models supported，L2 随后持续往一个没有任何
// 模型的站上烧 token。
//
// 判据用「首个非空白字节是 [」而不是「解出来非 nil」：`[]` 解出的也是空
// slice，两者无法靠结果区分，只能看输入的形状。
func decodeJSONArray(raw json.RawMessage) ([]json.RawMessage, bool) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false
	}
	var list []json.RawMessage
	if json.Unmarshal(trimmed, &list) != nil {
		return nil, false
	}
	return list, true
}

func (d *incrementalDecoder) eventFromObject(eventName string, object map[string]json.RawMessage, payload []byte) ([]ProtocolEvent, error) {
	if raw, ok := object["error"]; ok && carriesError(raw) {
		return []ProtocolEvent{remoteErrorEvent(eventName, raw)}, nil
	}
	if d.spec.Endpoint == model.EndpointModels {
		if raw, ok := object["data"]; ok {
			if list, isList := decodeJSONArray(raw); isList {
				return []ProtocolEvent{{Kind: EventModelList, EventName: "model_list", Semantic: true,
					ModelListRecognized: true, ModelCount: len(list)}}, nil
			}
		}
		// 名字用 model_list 而不是留空：普通 JSON 没有 event 名，而一个空名字
		// 的事件在诊断里说明不了任何事（「这个站的 /models 返回了什么」是排查
		// 第一个要问的问题）。ModelListRecognized 为 false 已经表达了「不是
		// 一份可用的列表」，两者合起来才是完整事实。
		return []ProtocolEvent{{Kind: EventMetadata, EventName: modelListEventName(eventName)}}, nil
	}
	if d.spec.Endpoint == model.EndpointCountTokens {
		if value := tokenCount(object, "input_tokens"); value > 0 {
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
	return []ProtocolEvent{event}, nil
}

func classifyAnthropic(event *ProtocolEvent, name string, object map[string]json.RawMessage) {
	if name == "message_delta" {
		if usage, ok := object["usage"]; ok {
			var value map[string]json.RawMessage
			if json.Unmarshal(usage, &value) == nil {
				// 只记数，不设 Semantic：token 数不是内容证据（§8.8）。
				event.OutputTokens = tokenCount(value, "output_tokens")
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

// responsesSemanticFields 把 Responses 的 delta 事件名映射到内容类别。
// 提到包级：每个事件都重建一次这张表会在解析热路径上白分配一次 map。
var responsesSemanticFields = map[string]string{
	"response.output_text.delta":             "text",
	"response.reasoning_summary_text.delta":  "reasoning",
	"response.refusal.delta":                 "refusal",
	"response.function_call_arguments.delta": "function_args",
}

func classifyResponses(event *ProtocolEvent, name string, object map[string]json.RawMessage) {
	if semanticKind, ok := responsesSemanticFields[name]; ok {
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
						event.OutputTokens = tokenCount(values, "output_tokens")
					}
				}
			}
		}
	}
}

// chatSemanticFields 是 Chat delta 里的内容字段，**按优先级排列**。
//
// 用切片而不是 map：map 的遍历顺序是随机的，而一个 chunk 里同时出现 content
// 和 refusal 是真实形态（拒答时个别站两个都填）。用 map 挑字段的话，同一份
// 字节在两次运行里给出不同的 SemanticKind，而 P0-08 要按它分流「真内容」与
// 「拒答」—— 于是同一个站会随机地被判成两种结果，且复现不了。
var chatSemanticFields = []struct {
	field string
	kind  string
}{
	{"content", "text"},
	{"reasoning_content", "reasoning"},
	{"refusal", "refusal"},
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
		for _, candidate := range chatSemanticFields {
			value := delta[candidate.field]
			if len(value) == 0 {
				value = message[candidate.field]
			}
			if nonEmptyString(value) {
				event.Semantic = true
				event.SemanticKind = candidate.kind
				break
			}
		}
		if nonEmptyToolArguments(delta["tool_calls"]) {
			event.Semantic = true
			event.SemanticKind = "tool"
		}
		if nonEmptyCallArguments(delta["function_call"]) {
			event.Semantic = true
			event.SemanticKind = "function_args"
		}
	}
	if usage, ok := object["usage"]; ok {
		var values map[string]json.RawMessage
		if json.Unmarshal(usage, &values) == nil {
			event.OutputTokens = tokenCount(values, "completion_tokens")
			if event.OutputTokens == 0 {
				event.OutputTokens = tokenCount(values, "output_tokens")
			}
		}
	}
	if name == "done" {
		event.Kind = EventProtocolEnd
		event.Semantic = false
	}
}

// nonEmptyToolArguments 检查 tool_calls 里是否真的有非空 arguments。
//
// 不能用 `bytes.Contains(raw, "arguments")`：`"arguments":""` 与
// `{"name":"arguments"}` 都会命中，于是空 delta 被算成「模型在生成」——
// 与 §8.8 对空 delta 的要求正好相反，而这两种形态恰恰是假活站的典型输出。
func nonEmptyToolArguments(raw json.RawMessage) bool {
	var calls []map[string]json.RawMessage
	if json.Unmarshal(raw, &calls) != nil {
		return false
	}
	for _, call := range calls {
		if nonEmptyCallArguments(call["function"]) {
			return true
		}
	}
	return false
}

func nonEmptyCallArguments(raw json.RawMessage) bool {
	var call map[string]json.RawMessage
	if json.Unmarshal(raw, &call) != nil {
		return false
	}
	return nonEmptyString(call["arguments"])
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

// tokenCount 读一个 token 计数，负数按「没有可信数字」丢掉。
//
// P0-08 要把 usage 事件单调累加成 Decision 的 token 总数。让 -5 流进去的话
// 总和会往回走，于是「这次探活比上次少花了 token」这种不可能的结论会进数据库，
// 而源头在这里 —— 到那一层已经查不出是哪个站发的。
func tokenCount(object map[string]json.RawMessage, name string) int64 {
	value, ok := integerField(object, name)
	if !ok || value < 0 {
		return 0
	}
	return value
}

func nonEmptyString(raw json.RawMessage) bool {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return false
	}
	var value string
	return json.Unmarshal(raw, &value) == nil && value != ""
}

// carriesError 回答「这个 error 字段里真的有错误吗」。
//
// 中转站表达「本次无错误」的拼法不统一：null、false、空串、空对象都见过。
// 把它们当成真错误的话，一个正常工作的站会被判成「上游报错」，而正文里根本
// 没有错误信息可展示 —— UI 上只会出现一个没有原因的失败。
func carriesError(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	switch string(trimmed) {
	case "", "null", "false", `""`, "{}", "[]":
		return false
	}
	return true
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
