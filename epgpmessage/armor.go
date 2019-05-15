/*
Copyright (c) 2016 emersion (Simon Ser)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/


package epgpmessage

import (
	"bufio"
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
)

// Armored type for PGP encrypted messages.
const pgpMessageType = "PGP MESSAGE"

var armorTag = []byte("-----BEGIN "+pgpMessageType+"-----")

func decryptArmored(in io.Reader, kr openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	br := bufio.NewReaderSize(in, len(armorTag))

	// Read all empty lines at the begining
	var line []byte
	var isPrefix bool
	for len(line) == 0 {
		var err error
		line, isPrefix, err = br.ReadLine()
		if err != nil {
			return nil, err
		}

		line = bytes.TrimSpace(line)
	}

	prefix := line
	if !isPrefix {
		// isPrefix is set to true if the line was too long to be read entirely
		prefix = append(prefix, []byte("\r\n")...)
	}

	// bufio.Reader doesn't consume the newline after the armor tag
	in = io.MultiReader(bytes.NewReader(prefix), in)
	if isPrefix || !bytes.Equal(line, armorTag) {
		// Not encrypted
		return &openpgp.MessageDetails{UnverifiedBody: in}, nil
	}

	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}

	return decrypt(block.Body, kr)
}

// An io.WriteCloser that both encrypts and armors data.
type armorEncryptWriter struct {
	aw io.WriteCloser // Armored writer
	ew io.WriteCloser // Encrypted writer
}

func (w *armorEncryptWriter) Write(b []byte) (n int, err error) {
	return w.ew.Write(b)
}

func (w *armorEncryptWriter) Close() (err error) {
	if err = w.ew.Close(); err != nil {
		return
	}
	err = w.aw.Close()
	return
}

func encryptArmored(out io.Writer, to []*openpgp.Entity, signed *openpgp.Entity) (io.WriteCloser, error) {
	aw, err := armor.Encode(out, pgpMessageType, nil)
	if err != nil {
		return nil, err
	}

	ew, err := encrypt(aw, to, signed)
	if err != nil {
		return nil, err
	}

	return &armorEncryptWriter{aw: aw, ew: ew}, err
}
