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


package epgpmessage

import (
	"io"
	"log"
	"strings"

	"bytes"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
	"golang.org/x/crypto/openpgp"
)

func decryptEntity(mw *message.Writer, e *message.Entity, kr openpgp.KeyRing) error {
	// TODO: this function should change headers

	if mr := e.MultipartReader(); mr != nil {
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}

			pw, err := mw.CreatePart(p.Header)
			if err != nil {
				return err
			}

			if err := decryptEntity(pw, p, kr); err != nil {
				log.Println("WARN: cannot decrypt child part:", err)
			}
			pw.Close()
		}
	} else {
		// A normal part, just decrypt it

		mediaType, _, err := e.Header.ContentType()
		if err != nil {
			log.Println("WARN: cannot parse Content-Type:", err)
			mediaType = "text/plain"
		}
		isPlainText := strings.HasPrefix(mediaType, "text/")

		var md *openpgp.MessageDetails
		if mediaType == "application/pgp-encrypted" {
			// An encrypted binary part
			md, err = decrypt(e.Body, kr)
		} else if isPlainText {
			// The message text, maybe encrypted with inline PGP
			md, err = decryptArmored(e.Body, kr)
		} else {
			// An unencrypted binary part
			md = &openpgp.MessageDetails{UnverifiedBody: e.Body}
			err = nil
		}
		if err != nil {
			return err
		}

		if _, err := io.Copy(mw, md.UnverifiedBody); err != nil {
			return err
		}

		// Fail if the signature is incorrect
		if err := md.SignatureError; err != nil {
			return err
		}
	}

	return nil
}

func DecryptWrap(w io.Writer, r io.Reader, kr openpgp.KeyRing) error {
	h,r2,err := parseMessageHeader(r)
	if err != nil {
		return err
	}
	
	// Content-Type: text/plain; rfc822=pgp
	if checkIsWrap(h) {
		md, err := decryptArmored(r2, kr)
		if err!=nil { return err }
		if md.SignatureError!=nil { return md.SignatureError }
		return DecryptWrap(w, readerAll{md.UnverifiedBody}, kr)
	}
	
	buf := new(bytes.Buffer)
	
	/* Write the original header */
	if err = textproto.WriteHeader(buf,h.Header); err != nil {
		log.Println("WARN: header serialization error: ",err)
		return err
	}
	if _,err = buf.WriteTo(w); err != nil {
		return err
	}
	
	/* Write the original body */
	if _, err := io.Copy(w, r2); err != nil {
		return err
	}
	
	return nil
}

func DecryptFull(w io.Writer, r io.Reader, kr openpgp.KeyRing) error {
	h,r2,err := parseMessageHeader(r)
	if err != nil {
		return err
	}
	
	// Content-Type: text/plain; rfc822=pgp
	if checkIsWrap(h) {
		md, err := decryptArmored(r2, kr)
		if err!=nil { return err }
		if md.SignatureError!=nil { return md.SignatureError }
		return DecryptFull(w, readerAll{md.UnverifiedBody}, kr)
	}
	
	e, err := message.New(h,r2)
	if err != nil {
		return err
	}
	if t,m,err := e.Header.ContentType(); err==nil {
		m["charset"] = "utf-8"
		e.Header.SetContentType(t,m)
	}

	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	if err := decryptEntity(mw, e, kr); err != nil {
		return err
	}
	return mw.Close()
}

func DecryptRegular(w io.Writer, r io.Reader, kr openpgp.KeyRing) error {
	e, err := message.Read(r)
	if err != nil {
		return err
	}
	if t,m,err := e.Header.ContentType(); err==nil {
		m["charset"] = "utf-8"
		e.Header.SetContentType(t,m)
	}

	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	if err := decryptEntity(mw, e, kr); err != nil {
		return err
	}
	return mw.Close()
}

func encryptEntity(mw *message.Writer, e *message.Entity, to []*openpgp.Entity, signed *openpgp.Entity) error {
	// TODO: this function should change headers (e.g. set MIME type to application/pgp-encrypted)

	if mr := e.MultipartReader(); mr != nil {
		// This is a multipart part, parse and encrypt each part

		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}

			if t,m,err := p.Header.ContentType(); err==nil {
				m["charset"] = "utf-8"
				p.Header.SetContentType(t,m)
			}
			pw, err := mw.CreatePart(p.Header)
			if err != nil {
				return err
			}

			if err := encryptEntity(pw, p, to, signed); err != nil {
				return err
			}
			pw.Close()
		}
	} else {
		// A normal part, just encrypt it

		mediaType, _, err := e.Header.ContentType()
		if err != nil {
			log.Println("WARN: cannot parse Content-Type:", err)
			mediaType = "text/plain"
		}

		disp, _, err := e.Header.ContentDisposition()
		if err != nil {
			log.Println("WARN: cannot parse Content-Disposition:", err)
		}

		var plaintext io.WriteCloser
		if strings.HasPrefix(mediaType, "text/") && disp != "attachment" {
			// The message text, encrypt it with inline PGP
			plaintext, err = encryptArmored(mw, to, signed)
		} else {
			plaintext, err = encrypt(mw, to, signed)
		}
		if err != nil {
			return err
		}
		defer plaintext.Close()

		if _, err := io.Copy(plaintext, e.Body); err != nil {
			return err
		}
	}

	return nil
}

func EncryptWrap(w io.Writer, r io.Reader, to []*openpgp.Entity, signed *openpgp.Entity) error {
	h,r2,err := parseMessageHeader(r)
	if err != nil {
		return err
	}
	
	var hd message.Header
	for i := h.FieldsByKey("Sender"); i.Next() ; { hd.Add("Sender",i.Value()) }
	for i := h.FieldsByKey("From"); i.Next() ; { hd.Add("From",i.Value()) }
	for i := h.FieldsByKey("To"); i.Next() ; { hd.Add("To",i.Value()) }
	for i := h.FieldsByKey("Message-Id"); i.Next() ; { hd.Add("Message-ID",i.Value()) }
	hd.Add("Subject","A Secret message (PGP)")
	hd.SetContentType("text/plain",map[string]string{"rfc822":"pgp"})
	hd.Set("X-Epgp-Wrapped",hd.Get("Content-Type"))
	
	mw, err := message.CreateWriter(w, hd)
	plaintext, err := encryptArmored(mw, to, signed)
	
	buf := new(bytes.Buffer)
	
	/* Write the original header */
	if err = textproto.WriteHeader(buf,h.Header); err != nil {
		log.Println("WARN: header serialization error: ",err)
		return err
	}
	if _,err = buf.WriteTo(plaintext); err != nil {
		return err
	}
	
	/* Write the original body */
	if _, err := io.Copy(plaintext, r2); err != nil {
		return err
	}
	
	return plaintext.Close()
}

func EncryptRegular(w io.Writer, r io.Reader, to []*openpgp.Entity, signed *openpgp.Entity) error {
	e, err := message.Read(r)
	if err != nil {
		return err
	}
	
	if t,m,err := e.Header.ContentType(); err==nil {
		m["charset"] = "utf-8"
		e.Header.SetContentType(t,m)
	}
	mw, err := message.CreateWriter(w, e.Header)
	if err != nil {
		return err
	}
	if err := encryptEntity(mw, e, to, signed); err != nil {
		return err
	}
	return mw.Close()
}
