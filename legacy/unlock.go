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

package pgpmail


import (
	"sync"

	"golang.org/x/crypto/openpgp"
)

type UnlockFunction func(username, password string) (openpgp.EntityList, error)

func UnlockRemember(f UnlockFunction) UnlockFunction {
	cache := map[string]openpgp.EntityList{}
	return func(username, password string) (openpgp.EntityList, error) {
		if kr, ok := cache[username]; ok {
			return kr, nil
		}

		kr, err := f(username, password)
		if err != nil {
			return nil, err
		}

		cache[username] = kr
		return kr, nil
	}
}

func UnlockSync(f UnlockFunction) UnlockFunction {
	locker := &sync.Mutex{}
	return func(username, password string) (openpgp.EntityList, error) {
		locker.Lock()
		defer locker.Unlock()

		return f(username, password)
	}
}
