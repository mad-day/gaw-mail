/*
Copyright (c) 2019 Simon Schmidt
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


package imap

import (
	"bytes"
	"io"

	"golang.org/x/crypto/openpgp"

	"github.com/mad-day/gaw-mail/epgpmessage"
)

func decryptMessage(mode DecryptMode,kr openpgp.KeyRing, r io.Reader) (io.Reader, error) {
	b := new(bytes.Buffer)
	var err error
	switch mode {
	case DecryptRegular: err = epgpmessage.DecryptRegular(b, r, kr)
	case DecryptWrap: err = epgpmessage.DecryptWrap(b, r, kr)
	case DecryptFull: err = epgpmessage.DecryptFull(b, r, kr)
	default: err = epgpmessage.DecryptRegular(b, r, kr)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

func encryptMessage(mode EncryptMode,kr openpgp.EntityList, w io.Writer, r io.Reader) error {
	switch mode {
	case EncryptRegular: return epgpmessage.EncryptRegular(w, r, kr, kr[0])
	case EncryptWrap: return epgpmessage.EncryptWrap(w, r, kr, kr[0])
	default: return epgpmessage.EncryptRegular(w, r, kr, kr[0])
	}
}
