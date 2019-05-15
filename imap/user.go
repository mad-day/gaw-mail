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
	"github.com/emersion/go-imap/backend"

	"golang.org/x/crypto/openpgp"
)

type user struct {
	backend.User

	kr openpgp.EntityList
}

func (u *user) getMailbox(m backend.Mailbox) *mailbox {
	return &mailbox{m, u}
}

func (u *user) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	if mailboxes, err := u.User.ListMailboxes(subscribed); err != nil {
		return nil, err
	} else {
		for i, m := range mailboxes {
			mailboxes[i] = u.getMailbox(m)
		}
		return mailboxes, nil
	}
}

func (u *user) GetMailbox(name string) (backend.Mailbox, error) {
	if m, err := u.User.GetMailbox(name); err != nil {
		return nil, err
	} else {
		return u.getMailbox(m), nil
	}
}
