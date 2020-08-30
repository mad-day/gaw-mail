/*
Copyright (c) 2016 emersion

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

// Uses the local GPG key store.
package local

import (
	"bytes"
	"errors"
	"os/exec"

	"camlistore.org/pkg/misc/pinentry"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

func Unlock(username, _ string) (openpgp.EntityList, error) {
	// Request the password only once as it will be used both to export the
	// private key and to decrypt it
	req := &pinentry.Request{
		Desc: "Please enter the passphrase for your main PGP key.",
	}

	passphrase, err := req.GetPIN()
	if err != nil {
		return nil, err
	}

	// Export private key
	cmd := exec.Command("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", passphrase, "--export-secret-keys")

	b := &bytes.Buffer{}
	cmd.Stdout = b

	if err := cmd.Run(); err != nil {
		return nil, err
	}

	if b.Len() == 0 {
		return nil, errors.New("cannot find any local private key")
	}

	kr, err := openpgp.ReadKeyRing(b)
	if err != nil {
		return nil, err
	}

	// Build a list of keys to decrypt
	var keys []*packet.PrivateKey
	for _, e := range kr {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			keys = append(keys, e.PrivateKey)
		}

		// Entity.Subkeys can be used for encryption
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil {
				keys = append(keys, subKey.PrivateKey)
			}
		}
	}

	// Decrypt all private keys
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}

		if err = key.Decrypt([]byte(passphrase)); err != nil {
			return nil, err
		}
	}

	return kr, nil
}
