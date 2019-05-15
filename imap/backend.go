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


// Package imap provides a go-imap backend that encrypts and decrypts PGP
// messages.
package imap

import (
	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"

	"github.com/emersion/go-pgpmail"
)

type Backend struct {
	backend.Backend

	unlock pgpmail.UnlockFunction
}

func New(be backend.Backend, unlock pgpmail.UnlockFunction) *Backend {
	return &Backend{be, unlock}
}

func (be *Backend) Login(conn *imap.ConnInfo,username, password string) (backend.User, error) {
	if u, err := be.Backend.Login(conn,username, password); err != nil {
		return nil, err
	} else if kr, err := be.unlock(username, password); err != nil {
		return nil, err
	} else {
		return &user{u, kr}, nil
	}
}
