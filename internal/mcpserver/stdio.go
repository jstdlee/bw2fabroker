package mcpserver

import (
	"bufio"
	"context"
	"io"
	"strings"
)

// ServeStdio serves the protocol on stdin/stdout, one JSON object per line.
// A notification gets no answer. The call ends when the input ends.
func (s *Server) ServeStdio(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		msg, err := s.Handle(ctx, []byte(line))
		if err != nil {
			return err
		}
		if len(msg) == 0 {
			continue // notification
		}
		if err := writeMsg(out, msg); err != nil {
			return err
		}
	}
	return sc.Err()
}

// writeMsg writes one JSON object and a newline.
func writeMsg(w io.Writer, b []byte) error {
	_, err := w.Write(append(b, '\n'))
	return err
}
