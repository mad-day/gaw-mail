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
	"log"
	"strings"
	"math/rand"
	"fmt"

	"bytes"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
)

/* Somewhat identical to imap.Literal */
type Literal interface {
	io.Reader
	
	// Len returns the number of bytes of the literal.
	Len() int
}


type Cleaner func(h *message.Header)

func Radical(h *message.Header) {
	h.Set("Subject","(Deleted)")
	h.Del("Sender")
	h.Del("From")
	h.Del("To")
	h.Del("CC")
	h.Del("BCC")
	h.Del("Reply-To")
	
	h.Set("Sender","Unknown <unknown@none>")
	h.Set("From","Unknown <unknown@none>")
	h.Set("To","Unknown <unknown@none>")
}

/*
Encrypts the given Mail into an NGCRYPT message. The NGCRYPT message is a multipart-message with 1 or 2 parts,
each compressed and PGP encrypted (called "NGCRYPT MESSAGE" instead of "PGP MESSAGE").

The first part always contains the complete header.

The second part contains the body.

This is useful for Envelope-Fetching, as the IMAP-Gateway only needs
to fetch the first part from the server whilst delivering the Envelope to the client.
*/
func Encrypt(w io.Writer, mail Literal, to []*openpgp.Entity, signed *openpgp.Entity, c Cleaner) error {
	length := mail.Len()
	
	var h2 message.Header
	h,b,err := parseMessageHeader(mail)
	
	if err!=nil { return err }
	
	/* Store the original Mail header. */
	header := new(bytes.Buffer)
	if err = textproto.WriteHeader(header,h.Header); err != nil {
		log.Println("WARN: header error: ",err)
		return err
	}
	
	
	/* Strip header-fields */
	for i := h.Fields(); i.Next();  {
		k := strings.ToLower(i.Key())
		switch {
		case strings.HasPrefix(k,"content-"): i.Del() /* Strip Content-Type, Content-Disposition etc. */
		}
	}
	if c!=nil { c(&h) }
	
	hdr1 := make(map[string]string)
	
	h.SetContentType("multipart/mixed",map[string]string{"boundary":fmt.Sprintf("b_%x",rand.Int63())})
	h.Set("X-Ngcrypt-Pgp","enabled")
	h.Set("X-Ngcrypt-Size",fmt.Sprint(length)) /* RFC822.SIZE */
	
	hdr1["Rfc822-Size"] = fmt.Sprint(length)
	
	wr,err := message.CreateWriter(w,h);   if err!=nil { return err }
	
	// ----------------------------------------------------------------------------
	
	h2.SetContentType("text/plain",nil)
	h2.SetText("Subject","No Subject")
	
	pw,err := wr.CreatePart(h2);   if err!=nil { return err }
	enc,err := encodeNgcrypt(pw,to,signed,hdr1);   if err!=nil { return err }
	
	_,err = header.WriteTo(enc);   if err!=nil { return err }
	
	err = enc.Close();   if err!=nil { return err }
	err = pw.Close();   if err!=nil { return err }
	
	// ----------------------------------------------------------------------------
	
	pw,err = wr.CreatePart(h2);   if err!=nil { return err }
	enc,err = encodeNgcrypt(pw,to,signed,nil);   if err!=nil { return err }
	
	_,err = io.Copy(enc,b)
	if err!=nil { return err }
	
	err = enc.Close();   if err!=nil { return err }
	err = pw.Close();   if err!=nil { return err }
	
	return wr.Close()
}

/*
Decrypt the RFC822 header using Part-1 as input.
*/
func DecryptHeader(m1 Literal, kr openpgp.KeyRing) (hdr message.Header,size int, err0 error) {
	var rest bytes.Buffer
	var rd io.Reader
	var md *openpgp.MessageDetails
	var inh map[string]string
	m1,err0 = removeHeaderIfAny(m1)
	if err0!=nil { return }
	
	md,inh,err0 = decodeNcrypt2(m1,kr)
	if err0!=nil { return }
	
	fmt.Sscan(inh["Rfc822-Size"],&size)
	
	hdr,rd,err0 = parseMessageHeader(md.UnverifiedBody)
	
	rest.ReadFrom(rd)
	
	/* Propagate Signature errors. */
	if md.SignatureError!=nil && err0==nil { err0 = md.SignatureError }
	return
}

/*
Decrypt the RFC822 body using Part-2 as input.
*/
func DecryptBody(m2 Literal, kr openpgp.KeyRing) (body Literal,err0 error) {
	var md *openpgp.MessageDetails
	m2,err0 = removeHeaderIfAny(m2)
	if err0!=nil { return }
	
	md,_,err0 = decodeNcrypt2(m2,kr)
	if err0!=nil { return }
	
	buf := new(bytes.Buffer)
	_,err0 = buf.ReadFrom(md.UnverifiedBody)
	if err0!=nil { return }
	
	/* Propagate Signature errors. */
	if md.SignatureError!=nil && err0==nil { err0 = md.SignatureError }
	return
}

/*
Decrypt the RFC822 message using Part-1 and Part-2 as input.
*/
func DecryptMessage(w io.Writer,m1,m2 Literal, kr openpgp.KeyRing) (err0 error) {
	var md *openpgp.MessageDetails
	m1,err0 = removeHeaderIfAny(m1)
	if err0!=nil { return }
	
	md,err0 = decodeNcrypt(m1,kr)
	if err0!=nil { return }
	
	io.Copy(w,md.UnverifiedBody)
	
	
	if m2==nil { return }
	m2,err0 = removeHeaderIfAny(m2)
	if m2.Len()==0 { return }
	
	/* Propagate Signature errors. */
	err1 := md.SignatureError
	
	md,err0 = decodeNcrypt(m1,kr)
	if err0!=nil { return }
	
	io.Copy(w,md.UnverifiedBody)
	
	/* Propagate Signature errors. */
	if err1!=nil && err0==nil { err0 = err1 }
	if md.SignatureError!=nil && err0==nil { err0 = md.SignatureError }
	return
}

/*
Decrypt the RFC822 message using Part-1 and Part-2 as input.
*/
func DecryptWholeMessage(w io.Writer,r io.Reader, kr openpgp.KeyRing) (err0 error) {
	
	msg,err := message.Read(r)
	if err!=nil { return err }
	
	mr := msg.MultipartReader()
	if mr==nil {
		return fmt.Errorf("invalid ngcrypt message")
	}
	
	p,err := mr.NextPart()
	if err!=nil { return err }
	
	md,err := decodeNcrypt(p.Body,kr)
	if err!=nil { return err }
	
	_,err = io.Copy(w,md.UnverifiedBody)
	if err!=nil { return err }
	
	/* Propagate Signature errors. */
	if md.SignatureError!=nil && err0==nil { err0 = md.SignatureError }
	
	p,err = mr.NextPart()
	if err==io.EOF { return }
	if err!=nil { return err }
	
	md,err = decodeNcrypt(p.Body,kr)
	if err!=nil { return err }
	
	_,err = io.Copy(w,md.UnverifiedBody)
	if err!=nil { return err }
	
	/* Propagate Signature errors. */
	if md.SignatureError!=nil && err0==nil { err0 = md.SignatureError }
	
	return
}

