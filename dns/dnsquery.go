package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

type dnsquery struct {
	name       []byte
	querytype  uint16
	queryclass uint16
}

type DNSQuery interface {
	GetSize() int
	GetName() string
	GetType() uint16
	GetClass() uint16
}

func (h *dnsquery) GetSize() int {
	return (len(h.name) + 4)
}

func (h *dnsquery) GetName() string {
	return h.FormatName()
}

func (h *dnsquery) GetType() uint16 {
	return h.querytype
}
func (h *dnsquery) GetClass() uint16 {
	return h.queryclass
}

// DNSQUERYBuilder ..
type DNSQUERYBuilder interface {
	DNSQuery
	SetName(name string)
	SetType(t uint16)
	SetClass(c uint16)
	Pack() []byte
	TryFrom([]byte) error
	FormatName() string
}

//"www.google.com"--->"0x03www0x06google0x03com0x00"
//BuildDomainName ..
func BuildDomainName(domain string) []byte {

	var buffer bytes.Buffer
	segments := strings.Split(domain, ".")
	for _, seg := range segments {
		if len(seg) > 0 {
			binary.Write(&buffer, binary.BigEndian, byte(len(seg)))
			binary.Write(&buffer, binary.BigEndian, []byte(seg))
		}
	}
	binary.Write(&buffer, binary.BigEndian, byte(0x00))

	return buffer.Bytes()
}

//FormatDomainName ..
func FormatDomainName(content []byte) string {

	var sb strings.Builder
	if content == nil || len(content) == 0 {
		return sb.String()
	}

	for i := 0; content[i] != 0 && i < len(content); {
		n := int(content[i])
		i = i + 1 + n
		tmp := content[i-n : i]
		if len(tmp) > 0 {
			sb.Write(tmp)
			sb.WriteString(".")
		}

	}
	return sb.String()

}

func (h *dnsquery) SetName(name string) {
	h.name = BuildDomainName(name)
}

func (h *dnsquery) SetType(t uint16) {
	h.querytype = t
}

func (h *dnsquery) SetClass(c uint16) {
	h.queryclass = c
}

func (h *dnsquery) Pack() []byte {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, h.querytype)
	binary.Write(&buffer, binary.BigEndian, h.queryclass)
	return append(h.name, buffer.Bytes()...)

}

func (h *dnsquery) TryFrom(buf []byte) error {

	i := tryToGetNameLen(buf)
	if i == len(buf) {
		return errors.New("invalid data")
	}

	h.name = buf[:i]
	out := bytes.NewBuffer(buf[i : i+4])
	binary.Read(out, binary.BigEndian, &h.querytype)
	binary.Read(out, binary.BigEndian, &h.queryclass)
	return nil
}

func (h *dnsquery) FormatName() string {
	return FormatDomainName(h.name)
}

// NewDNSQuery ..
func NewDNSQuery() DNSQUERYBuilder {
	return &dnsquery{}
}
