package encrypter

import (
	"encoding/base64"
	"encoding/csv"
	"io"
)

var _ io.Writer = (*Writer)(nil)
var _ io.ReaderFrom = (*Writer)(nil)

const defaultReadFromSize = 1024 * 500
func NewWriter(key DerivedKey, writer io.Writer) *Writer {
	return &Writer{key: key, writer: csv.NewWriter(writer), Size: defaultReadFromSize}
}

type Writer struct {
	key DerivedKey
	writer *csv.Writer
	Size int
}

func (e *Writer) ReadFrom(src io.Reader) (written int64, err error) {
	buf := make([]byte, e.Size)
	var exit bool
	for {
		nr, err := src.Read(buf)
		if err == io.EOF {
			exit = true
			err = nil
		}
		if err != nil {
			return written, err
		}

		wr, err := e.Write(buf[:nr])
		written += int64(wr)
		if err != nil {
			return written, err
		}

		if exit {
			break
		}

	}

	return written, err
}

func (e *Writer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	data, err := EncryptWithDerivedKey(e.key, p)
	if err != nil {
		return 0, err
	}
	record := []string{base64.StdEncoding.EncodeToString(data)}
	err = e.writer.Write(record)
	e.writer.Flush()
	if err != nil {
		return 0, err
	}

	return len(p), nil
}
