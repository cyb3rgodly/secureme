package encrypter

import (
	"encoding/base64"
	"encoding/csv"
	"errors"
	"io"
)

func CopyToWriter(key []byte, encrypted io.Reader, dst io.Writer) error {
	reader := csv.NewReader(encrypted)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if len(record) != 1 {
			return errors.New("bad data detected")
		}

		data, err := base64.StdEncoding.DecodeString(record[0])
		if err != nil {
			return err
		}

		decrypted, err := Decrypt(key, data)
		if err != nil {
			return err
		}

		if _, err = dst.Write(decrypted); err != nil {
			return err
		}
	}
}
