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


package ngcrypt

import (
	"io"
	"compress/flate"
	
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	//"fmt"
)

const ngcryptMessageType = "NGCRYPT MESSAGE"

type stack []io.Closer
func (s stack) Close() (err2 error) {
	for _,c := range s {
		err := c.Close()
		if err2==nil { err2 = err }
	}
	return
}

type wriClo struct {
	io.Writer
	stack
}

func encodeNgcrypt(out io.Writer, to []*openpgp.Entity, signed *openpgp.Entity, args map[string]string) (io.WriteCloser, error) {
	aw, err := armor.Encode(out, ngcryptMessageType, args)
	if err != nil {
		return nil, err
	}
	
	ew, err := encrypt(aw, to, signed)
	if err != nil {
		return nil, err
	}
	
	cw,err := flate.NewWriter(ew,1)
	if err != nil {
		return nil, err
	}
	
	return &wriClo{cw,stack{cw,ew,aw}}, err
}

func decodeNcrypt(in io.Reader, kr openpgp.KeyRing) (*openpgp.MessageDetails, error) {
	block,err := armor.Decode(in)
	if err!=nil { return nil,err }
	
	dr,err := decrypt(block.Body,kr)
	
	if err == nil {
		/* If no error, decompress the body. */
		c := dr.UnverifiedBody
		uc := flate.NewReader(readerAll{c})
		dr.UnverifiedBody = uc
	}
	
	return dr,err
}
