package probe

import (
	"io"
	"time"
)

// trafficQueueReader is consumed by the Attempt's existing worker. It blocks
// only that bounded worker, releases each copied chunk when consumed, and makes
// upstream waiting distinguishable from active decoder CPU budget.
type trafficQueueReader struct {
	observer *trafficObserver
	current  []byte
	offset   int
	waited   time.Duration
}

func (reader *trafficQueueReader) release() {
	if reader.current != nil {
		reader.observer.m.copyBytes.Add(-int64(len(reader.current)))
		reader.current = nil
		reader.offset = 0
	}
}

func (reader *trafficQueueReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for reader.current == nil {
		var event trafficEvent
		select {
		case event = <-reader.observer.queue:
		default:
			select {
			case <-reader.observer.stop:
				return 0, io.EOF
			default:
			}
			start := time.Now()
			select {
			case event = <-reader.observer.queue:
			case <-reader.observer.stop:
				reader.waited += time.Since(start)
				continue
			}
			reader.waited += time.Since(start)
		}
		if len(event.chunk) == 0 {
			continue
		}
		reader.current = event.chunk
		capability := reader.observer.capability
		capability.lastInputAt = event.at
		if capability.firstByteAt.IsZero() {
			capability.firstByteAt = event.at
		}
	}
	n := copy(p, reader.current[reader.offset:])
	reader.offset += n
	if reader.offset == len(reader.current) {
		reader.release()
	}
	return n, nil
}

func (o *trafficObserver) decodeCompressed() {
	capability := o.capability
	source := &trafficQueueReader{observer: o}
	defer source.release()
	started := time.Now()
	decoded, err := NewContentDecoder(capability.encoding, source, ContentCodingLimits{
		MaxEncodedBytes: perAttemptCopyBudget, MaxDecodedBytes: trafficDecodedLimit, MaxWorkUnits: 4096,
	})
	capability.decodeWork += time.Since(started) - source.waited
	if err != nil {
		capability.decodeErr = err
		return
	}
	defer decoded.Close()
	buffer := make([]byte, 16<<10)
	for {
		started, waited := time.Now(), source.waited
		n, readErr := decoded.Read(buffer)
		capability.decodeWork += time.Since(started) - (source.waited - waited)
		if n > 0 {
			capability.feed(buffer[:n], capability.lastInputAt)
		}
		if capability.decodeErr != nil {
			return
		}
		if capability.decodeWork > trafficDecodeCPULimit {
			capability.decodeErr = errTrafficDecodeDeadline
			return
		}
		if readErr == io.EOF {
			return
		}
		if readErr != nil {
			capability.decodeErr = readErr
			return
		}
	}
}
