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


package imap

import (
	"bytes"
	"io"
	"log"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

type mailbox struct {
	backend.Mailbox

	u *user
}

func (m *mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	// TODO: support imap.BodySectionName.Partial
	// TODO: support imap.TextSpecifier

	// Only intercept messages if fetching body parts
	needsDecryption := false
	for _, item := range items {
		if _, err := imap.ParseBodySectionName(item); err == nil {
			needsDecryption = true
			break
		}
	}
	if !needsDecryption {
		return m.Mailbox.ListMessages(uid, seqSet, items, ch)
	}

	messages := make(chan *imap.Message)
	go func() {
		defer close(ch)

		for msg := range messages {
			for section, literal := range msg.Body {
				if section.Specifier != imap.EntireSpecifier {
					continue
				}

				r, err := decryptMessage(m.u.kr, literal)
				if err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				b := new(bytes.Buffer)
				if _, err := io.Copy(b, r); err != nil {
					log.Println("WARN: cannot decrypt part:", err)
					continue
				}

				msg.Body[section] = b
			}
			
			
			ch <- msg
		}
	}()

	return m.Mailbox.ListMessages(uid, seqSet, items, messages)
}

func (m *mailbox) CreateMessage(flags []string, date time.Time, r imap.Literal) error {
	b := new(bytes.Buffer)
	if err := encryptMessage(m.u.kr, b, r); err != nil {
		return err
	}
	return m.Mailbox.CreateMessage(flags, date, b)
}
