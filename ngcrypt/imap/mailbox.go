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
	"time"
	"io"
	"bufio"
	"fmt"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/backendutil"
	//"github.com/mad-day/gaw-mail/util/backendutil"
	"github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
	
	"github.com/mad-day/gaw-mail/ngcrypt"
	
	imapfetch "github.com/mad-day/gaw-mail/util/imap-fetch"
)

type mailbox struct {
	backend.Mailbox

	u *user
}

func filter(items []imap.FetchItem) (pass []imap.FetchItem, head,body,size,see bool) {
	pass = make([]imap.FetchItem,0,len(items)+2)
	
	for _,item := range items {
		switch item {
		case imap.FetchEnvelope: head = true
		case imap.FetchBody, imap.FetchBodyStructure: body = true
		case imap.FetchRFC822Size: size = true
		case imap.FetchFlags,imap.FetchInternalDate,imap.FetchUid:
			pass = append(pass,item)
		default:
			if section, err := imap.ParseBodySectionName(item); err==nil {
				if !section.Peek { see = true }
				item2,ok := imapfetch.Shortcut(section)
				if !ok {
					head = true
					body = true
				} else {
					switch item2 {
					case imap.FetchRFC822:
						head = true
						body = true
					case imap.FetchRFC822Header:
						head = true
					case imap.FetchRFC822Text:
						body = true
					}
				}
			} else {
				head = true
				body = true
				switch item {
				case imap.FetchRFC822, imap.FetchRFC822Text: see = true
				}
			}
		}
		
	}
	
	return
}
func parts(m map[*imap.BodySectionName]imap.Literal) (m1, m2 imap.Literal) {
	for k,v := range m {
		if len(k.Path)!=1 { continue }
		switch k.Path[0] {
		case 1: m1=v
		case 2: m2=v
		}
	}
	return
}
func headerPart(m map[*imap.BodySectionName]imap.Literal) (hdrl imap.Literal) {
	for k,v := range m {
		if len(k.Path)!=0 { continue }
		if k.Specifier!=imap.HeaderSpecifier { continue }
		hdrl = v
	}
	return
}


type entityPop func() (*message.Entity,error)
func epParse(b []byte) entityPop {
	return func() (*message.Entity,error) { return message.Read(bytes.NewReader(b)) }
}
func epHead(h message.Header) entityPop {
	r := bytes.NewReader([]byte{})
	return func() (*message.Entity,error) { return &message.Entity{Header:h,Body:r},nil }
}
func epBody(b io.Reader) entityPop {
	return func() (*message.Entity,error) { return &message.Entity{Body:b},nil }
}

func (m *mailbox) fetchHeadAndBody(msg *imap.Message) (entityPop,int,error) {
	m1,m2 := parts(msg.Body)
	if m1!=nil { return nil,0,io.EOF }
	if m2!=nil { return nil,0,io.EOF }
	b := new(bytes.Buffer)
	err := ngcrypt.DecryptMessage(b,m1,m2,m.u.kr)
	if err!=nil { return nil,0,err }
	size := b.Len()
	return epParse(b.Bytes()),size,nil
}
func (m *mailbox) fetchHead(msg *imap.Message) (entityPop,int,error) {
	m1,_ := parts(msg.Body)
	if m1!=nil { return nil,0,io.EOF }
	hdr,size,err := ngcrypt.DecryptHeader(m1,m.u.kr)
	if err!=nil { return nil,0,err }
	return epHead(hdr),size,nil
}
func (m *mailbox) fetchBody(msg *imap.Message) (entityPop,int,error) {
	_,m2 := parts(msg.Body)
	if m2!=nil { return nil,0,io.EOF }
	body,err := ngcrypt.DecryptBody(m2,m.u.kr)
	if err!=nil { return nil,0,err }
	return epBody(body),-1,nil
}

func (m *mailbox) fetchSize(msg *imap.Message) (entityPop,int,error) {
	hdrl := headerPart(msg.Body)
	if hdrl!=nil { return nil,0,io.EOF }
	h,err := textproto.ReadHeader(bufio.NewReader(hdrl))
	if err!=nil { return nil,0,err }
	var size int
	fmt.Sscan(h.Get("X-Ngcrypt-Size"),&size)
	return nil,size,nil
}

func toLiteral(r io.Reader) imap.Literal {
	buf := new(bytes.Buffer)
	buf.ReadFrom(r)
	return buf
}
func headerLiteral(h message.Header) imap.Literal {
	buf := new(bytes.Buffer)
	textproto.WriteHeader(buf,h.Header)
	return buf
}

func fetchNone(_ *imap.Message) (entityPop,int,error) { return nil,0,nil }

func (m *mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	pass,head,body,hsize,see := filter(items)
	
	/* Short-Cut. */
	if !( head||body||hsize ) {
		return m.Mailbox.ListMessages(uid, seqSet, items, ch)
	}
	/*
	 * If we fetch the Body, the step of fetching the outer header for the RFC822.SIZE is skipped.
	 * That means, we must compensate for this!
	 */
	if hsize && body { head = true }
	
	var fetcher func(m *imap.Message) (entityPop,int,error)
	
	if head {
		tx := new(imap.BodySectionName)
		tx.Path = []int{1}
		tx.Peek = !see
		pass = append(pass,tx.FetchItem())
	}
	if body {
		tx := new(imap.BodySectionName)
		tx.Path = []int{2}
		tx.Peek = !see
		pass = append(pass,tx.FetchItem())
	}
	
	if head && body {
		fetcher = m.fetchHeadAndBody
	} else if body {
		fetcher = m.fetchBody
	} else if head {
		fetcher = m.fetchHead
	} else if hsize {
		tx := new(imap.BodySectionName)
		tx.Specifier = imap.HeaderSpecifier
		tx.Peek = !see
		pass = append(pass,tx.FetchItem())
		fetcher = m.fetchHead
	} else {
		fetcher = fetchNone
	}
	
	messages := make(chan *imap.Message)
	go func() {
		defer close(ch)
		msgq:
		for msg := range messages {
			entPop,size,err := fetcher(msg)
			
			if err!=nil { continue } /* Skip on error! */
			
			fetched := imap.NewMessage(msg.SeqNum, items)
			
			for _, item := range items {
				switch item {
				case imap.FetchEnvelope:
					e,err := entPop()
					if err!=nil { continue msgq } /* Skip on error! */
					fetched.Envelope, _ = backendutil.FetchEnvelope(e.Header)
				case imap.FetchBody, imap.FetchBodyStructure:
					e,err := entPop()
					if err!=nil { continue msgq } /* Skip on error! */
					fetched.BodyStructure, _ = backendutil.FetchBodyStructure(e, item == imap.FetchBodyStructure)
				case imap.FetchFlags:
					fetched.Flags = msg.Flags
				case imap.FetchInternalDate:
					fetched.InternalDate = msg.InternalDate
				case imap.FetchRFC822Size:
					fetched.Size = uint32(size)
				case imap.FetchUid:
					fetched.Uid = msg.Uid
				default:
					section, err := imap.ParseBodySectionName(item)
					if err != nil {
						continue msgq /* Skip on error! */
					}
					
					e,err := entPop()
					
					if err!=nil { continue msgq } /* Skip on error! */
					
					item2,ok := imapfetch.Shortcut(section)
					if ok {
						switch item2 {
						//case imap.FetchRFC822:
						case imap.FetchRFC822Header:
							fetched.Body[section] = headerLiteral(e.Header)
							continue
						case imap.FetchRFC822Text:
							fetched.Body[section] = toLiteral(e.Body)
							continue
						}
					}
					
					l, err := backendutil.FetchBodySection(e, section)
					if err!=nil { continue msgq } /* Skip on error! */
					fetched.Body[section] = l
				}
			}
			
			ch <- fetched
		}
	}()

	return m.Mailbox.ListMessages(uid, seqSet, pass, messages)
}

type searchRequirement struct{
	body bool
}
func (s *searchRequirement) scan(c *imap.SearchCriteria) {
	for _, not := range c.Not { s.scan(not) }
	for _, or := range c.Or { s.scan(or[0]); s.scan(or[1]) }
	
	if len(c.Body)!=0 || len(c.Text)!=0 { s.body = true }
}

func (m *mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	/*
	First, check if encrypted search is enabled.
	*/
	if !m.u.be.has(FlagEnableSearch) {
		return m.Mailbox.SearchMessages(uid,criteria)
	}
	var sr searchRequirement
	sr.scan(criteria)
	
	pass := make([]imap.FetchItem,0,9)
	
	pass = append(pass,imap.FetchUid,imap.FetchInternalDate,imap.FetchFlags)
	{ /* Encrypted Envelope/Header --- REQUIRED */
		tx := new(imap.BodySectionName)
		tx.Path = []int{1}
		tx.Peek = true
		pass = append(pass,tx.FetchItem())
	}
	if sr.body { /* Encrypted Body. --- OPTIONAL */
		tx := new(imap.BodySectionName)
		tx.Path = []int{2}
		tx.Peek = true
		pass = append(pass,tx.FetchItem())
	}
	
	var fetcher func(m *imap.Message) (entityPop,int,error)
	if sr.body {
		fetcher = m.fetchHeadAndBody
	} else {
		fetcher = m.fetchHead
	}
	
	messages := make(chan *imap.Message)
	
	minf,err := m.Mailbox.Status([]imap.StatusItem{imap.StatusMessages})
	if err!=nil { return nil,err }
	
	seqset := new(imap.SeqSet)
	seqset.AddRange(1, minf.Messages)
	go m.Mailbox.ListMessages(false, seqset, pass, messages)
	
	u := make([]uint32,0,minf.Messages)
	
	for msg := range messages {
		entPop,_,err := fetcher(msg)
		if err!=nil { continue }
		ent,err := entPop()
		if err!=nil { continue }
		ok,err := backendutil.Match(ent, msg.SeqNum, msg.Uid, msg.InternalDate, msg.Flags, criteria)
		if err!=nil { continue }
		if ok {
			if uid {
				u = append(u,msg.Uid)
			} else {
				u = append(u,msg.SeqNum)
			}
		}
	}
	
	return u,nil
}

func (m *mailbox) CreateMessage(flags []string, date time.Time, r imap.Literal) error {
	b := new(bytes.Buffer)
	kr := m.u.kr
	
	clnr := m.u.be.Cleaner
	if clnr==nil { clnr = ngcrypt.Radical }
	if err := ngcrypt.Encrypt(b, r, kr, kr[0], clnr); err != nil {
		return err
	}
	return m.Mailbox.CreateMessage(flags, date, b)
}

