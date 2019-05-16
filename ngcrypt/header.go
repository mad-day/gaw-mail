/*
Copyright (c) 2019 Simon Schmidt

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
	"bufio"
	"io"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
	
	"log"
	"bytes"
)

type debugger struct {
	io.Reader
}
func (d debugger) Read(b []byte) (i int,e error) {
	i,e = d.Reader.Read(b)
	log.Printf("%p.Read(%d) -> %d,%v\n",d.Reader,len(b),i,e)
	return
}

type readerAll struct {
	io.Reader
}
func (r readerAll) Read(b []byte) (i int,e error) {
	i,e = io.ReadFull(r.Reader,b)
	if e==io.ErrUnexpectedEOF { e = io.EOF }
	return
}

func parseMessageHeader(r io.Reader) (message.Header,io.Reader,error) {
	br := bufio.NewReader(r)
	h, err := textproto.ReadHeader(br)
	if err != nil {
		return message.Header{}, nil, err
	}
	
	return message.Header{h}, br, nil
}

func tobuf(l Literal) (b *bytes.Buffer,e error) {
	b,_ = l.(*bytes.Buffer)
	if b!=nil { return }
	b = new(bytes.Buffer)
	_,e = b.ReadFrom(l)
	return
}

// -----BEGIN
/*
"-----BEGIN NGCRYPT MESSAGE-----"
*/

var tagprefix = []byte("-----BEGIN")

func removeHeaderIfAny(l Literal) (nl Literal, err error) {
	var b *bytes.Buffer
	b,err = tobuf(l)
	if err!=nil { return }
	nl = b
	for {
		if bytes.HasPrefix(b.Bytes(),tagprefix) { break }
		i := bytes.IndexByte(b.Bytes(),'\n')
		if i<=0 { break }
		b.Next(i)
	}
	return
}


