package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

//AnswerDNS ...
type AnswerDNS struct {
	Name  []byte
	Type  uint16
	Class uint16
	TTL   uint32
	RDLen uint16
	RDATA []byte
}

//Answer ...
type Answer interface {
	GetName() []byte
	GetType() uint16
	GetClass() uint16
	GetTTL() uint32
	GetLen() uint16
	GetRData() []byte
	FormatR(full []byte) string
	GetSize() int
	TryFrom([]byte) error
	FormatName(full []byte) string
	Pack() []byte
}

func (a *AnswerDNS) GetName() []byte {
	return a.Name
}
func (a *AnswerDNS) GetType() uint16 {
	return a.Type
}
func (a *AnswerDNS) GetClass() uint16 {
	return a.Class
}

func (a *AnswerDNS) GetTTL() uint32 {
	return a.TTL
}
func (a *AnswerDNS) GetLen() uint16 {
	return a.RDLen
}

func (a *AnswerDNS) GetRData() []byte {
	return a.RDATA
}

func (a *AnswerDNS) FormatR(full []byte) string {

	if a.Type == 0x5 && a.Class == 0x1 {
		return formatANName(a.RDATA, full)

	} else if (a.Type == 0x1 || a.Type == 0x1C) && a.Class == 0x1 {
		ip := net.IP(a.RDATA)
		return ip.String()

	} else {
		var sb strings.Builder
		sb.Write(a.RDATA)
		return sb.String()
	}
}
func (a *AnswerDNS) GetSize() int {

	return 2 + 2 + 2 + 4 + 2 + int(a.RDLen)
}

func (a *AnswerDNS) TryFrom(in []byte) error {
	fmt.Println(in)
	namel := tryToGetNameLen(in)
	if namel >= len(in) {
		return errors.New("does not support it. because data is invalid")
	}

	a.Name = in[:namel]
	a.Type = (uint16(in[namel]) << 8) + uint16(in[namel+1])
	a.Class = (uint16(in[namel+2]) << 8) + uint16(in[namel+3])
	a.TTL = (uint32(in[namel+4]) << 24) + (uint32(in[namel+5]) << 16) + (uint32(in[namel+6]) << 8) + uint32(in[namel+7])
	a.RDLen = (uint16(in[namel+8]) << 8) + uint16(in[namel+9])
	a.RDATA = in[namel+10 : namel+10+int(a.RDLen)]
	return nil
}

func tryToGetNameLen(name []byte) int {

	if name == nil || len(name) < 1 {
		return 0
	}

	i := 0
	for {
		l := name[i]
		i++
		if l == 0 {
			break
		}

		t := (l >> 6) & 0x3
		if t == 0x3 {
			i++
			break
		}
		i = i + int(l)
	}
	return i
}

func (a *AnswerDNS) FormatName(full []byte) string {
	return formatANName(a.Name, full)
}

func (a *AnswerDNS) Pack() []byte {

	buffer := bytes.NewBuffer(a.Name)

	var sb bytes.Buffer
	binary.Write(&sb, binary.BigEndian, a.Type)
	binary.Write(&sb, binary.BigEndian, a.Class)
	binary.Write(&sb, binary.BigEndian, a.TTL)
	binary.Write(&sb, binary.BigEndian, a.RDLen)
	buffer.Write(sb.Bytes())
	buffer.Write(a.RDATA)
	return buffer.Bytes()
}

//NewDNSAnswer ..
func NewDNSAnswer() Answer {
	return &AnswerDNS{}
}

func formatANName(name, table []byte) string {
	p := name

	var sb strings.Builder
	for i := 0; p[i] != 0; {
		t := (p[i] >> 6) & 0x3
		if t == 0x3 {
			v := p[i] & 0x3f
			offset := (uint16(v) << 8) + uint16(p[i+1])
			p = table[offset:]
			i = 0
			continue
		}

		n := int(p[i])
		i = i + 1 + n
		tmp := p[i-n : i]
		if len(tmp) > 0 {
			sb.Write(tmp)
			sb.WriteString(".")
		}
	}

	return sb.String()

}
