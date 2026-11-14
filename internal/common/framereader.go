package common

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// LineReader wraps bufio.Reader for reading newline-delimited JSON frames
// (Envelope or StreamHeader) off a stream, with a generous max line size so
// a malformed/garbage peer can't wedge us by sending an unterminated line
// forever (bufio.Scanner's default 64KB token limit already protects
// against that; we just make it explicit here for clarity and raise it
// slightly since Hello payloads with many routes can be chunky).
type LineReader struct {
	r *bufio.Reader
}

func NewLineReader(r io.Reader) *LineReader {
	return &LineReader{r: bufio.NewReaderSize(r, 4096)}
}

// Read lets a LineReader double as a plain io.Reader once the caller is
// done pulling framed lines off the front of the stream (see
// server.prefixedConn): any bytes already buffered internally are
// returned first, so nothing read ahead during ReadHeader/ReadEnvelope is
// ever lost.
func (lr *LineReader) Read(p []byte) (int, error) {
	return lr.r.Read(p)
}

func (lr *LineReader) ReadEnvelope() (Envelope, error) {
	line, err := lr.readLine()
	if err != nil {
		return Envelope{}, err
	}
	var env Envelope
	if err := json.Unmarshal(line, &env); err != nil {
		return Envelope{}, fmt.Errorf("decoding envelope: %w", err)
	}
	return env, nil
}

func (lr *LineReader) ReadHeader() (StreamHeader, error) {
	line, err := lr.readLine()
	if err != nil {
		return StreamHeader{}, err
	}
	var h StreamHeader
	if err := json.Unmarshal(line, &h); err != nil {
		return StreamHeader{}, fmt.Errorf("decoding stream header: %w", err)
	}
	return h, nil
}

func (lr *LineReader) readLine() ([]byte, error) {
	const maxLine = 1 << 20 // 1MiB hard ceiling against a hostile/broken peer
	line, err := lr.r.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		// Line longer than the internal buffer: keep reading until '\n'
		// or we blow the hard ceiling, then give up loudly instead of
		// silently truncating/misparsing.
		buf := append([]byte{}, line...)
		for len(buf) < maxLine {
			more, err2 := lr.r.ReadSlice('\n')
			buf = append(buf, more...)
			if err2 == nil {
				return buf, nil
			}
			if err2 != bufio.ErrBufferFull {
				return nil, err2
			}
		}
		return nil, fmt.Errorf("line exceeded %d bytes, dropping connection", maxLine)
	}
	return line, err
}

// Unmarshal is a small helper so callers can decode Envelope.Payload without
// importing encoding/json everywhere.
func Unmarshal(raw json.RawMessage, v any) error {
	return json.Unmarshal(raw, v)
}

// PrefixedConn adapts a raw connection whose first line has already been
// consumed by a LineReader (to read a StreamHeader/Envelope) back into a
// plain io.ReadWriteCloser that continues exactly where the header left
// off. Both the server (relaying a "nested" stream one level deeper) and
// the agent (relaying a chained child agent's raw connection) need this
// exact same adapter, which is why it lives here instead of being
// duplicated in both packages.
type PrefixedConn struct {
	rwc io.ReadWriteCloser
	lr  *LineReader
}

func NewPrefixedConn(rwc io.ReadWriteCloser, lr *LineReader) *PrefixedConn {
	return &PrefixedConn{rwc: rwc, lr: lr}
}

func (p *PrefixedConn) Read(b []byte) (int, error)  { return p.lr.Read(b) }
func (p *PrefixedConn) Write(b []byte) (int, error) { return p.rwc.Write(b) }
func (p *PrefixedConn) Close() error                { return p.rwc.Close() }
