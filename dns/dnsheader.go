package dns

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type dnsheader struct {
	// ------------2bytes----------------
	ID uint16 // full bits

	//-------------1byte-----------------
	QR     bool   // 1 bit
	OPCODE uint16 // 4 bits
	AA     bool   // 1 bit
	TC     bool   // 1 bit
	RD     bool   // 1 bit

	//-------------1byte-----------------
	RA    bool   // 1 bit
	Z     uint16 // 3 bits
	RCODE uint16 // 4 bits
	//-----------------------------------

	QDCOUNT uint16
	ANCOUNT uint16
	NSCOUNT uint16
	ARCOUNT uint16
}

type DNSHeader interface {
	GetID() uint16
	GetQR() bool
	GetOPCode() uint8
	GetAA() bool
	GetTC() bool
	GetRD() bool
	GetRA() bool
	GetZ() uint8
	GetRCCode() uint8
	GetQDCount() uint16
	GetANCount() uint16
	GetNSCount() uint16
	GetARCount() uint16
	GetSize() int
}

func (h *dnsheader) GetSize() int {
	return 12
}

func (h *dnsheader) GetID() uint16 {
	return h.ID
}

func (h *dnsheader) GetQR() bool {
	return h.QR
}

func (h *dnsheader) GetOPCode() uint8 {
	return uint8(h.OPCODE)
}
func (h *dnsheader) GetAA() bool {
	return h.AA
}
func (h *dnsheader) GetTC() bool {
	return h.TC
}
func (h *dnsheader) GetRD() bool {
	return h.RD
}
func (h *dnsheader) GetRA() bool {
	return h.RA
}
func (h *dnsheader) GetZ() uint8 {
	return (uint8)(h.Z)
}
func (h *dnsheader) GetRCCode() uint8 {
	return uint8(h.RCODE)
}
func (h *dnsheader) GetQDCount() uint16 {
	return h.QDCOUNT
}
func (h *dnsheader) GetANCount() uint16 {
	return h.ANCOUNT
}
func (h *dnsheader) GetNSCount() uint16 {
	return h.NSCOUNT
}
func (h *dnsheader) GetARCount() uint16 {
	return h.ARCOUNT
}

// DNSHeaderBuilder ...
type DNSHeaderBuilder interface {
	DNSHeader
	SetID(id uint16)
	SetQR(qr bool)
	SetOPCode(op uint8)
	SetAA(aa bool)
	SetTC(tc bool)
	SetRD(rd bool)
	SetRA(ra bool)
	SetZ(z uint8)
	SetRCODE(code uint8)
	SetQDCount(c uint16)
	SetANCount(c uint16)
	SetNSCount(c uint16)
	SetARCount(c uint16)
	Pack() []byte
	TryFrom([]byte) error
}

func (h *dnsheader) SetID(id uint16) {
	h.ID = id
}

func (h *dnsheader) SetQR(qr bool) {
	h.QR = qr
}

func (h *dnsheader) SetOPCode(op uint8) {
	h.OPCODE = 0xf & uint16(op)
}

func (h *dnsheader) SetAA(aa bool) {
	h.AA = aa
}

func (h *dnsheader) SetTC(tc bool) {
	h.TC = tc
}
func (h *dnsheader) SetRD(rd bool) {
	h.RD = rd
}
func (h *dnsheader) SetRA(ra bool) {
	h.RA = ra
}
func (h *dnsheader) SetZ(z uint8) {
	h.Z = 0x7 & uint16(z)
}
func (h *dnsheader) SetRCODE(code uint8) {
	h.RCODE = 0xf & uint16(code)
}
func (h *dnsheader) SetQDCount(c uint16) {
	h.QDCOUNT = c
}
func (h *dnsheader) SetANCount(c uint16) {
	h.ANCOUNT = c
}
func (h *dnsheader) SetNSCount(c uint16) {
	h.NSCOUNT = c
}
func (h *dnsheader) SetARCount(c uint16) {
	h.ARCOUNT = c
}

func (h *dnsheader) Pack() []byte {

	var s uint16
	s = h.RCODE << 12
	s = s + (h.Z << 9)
	if h.RA {
		s = s + (1 << 8)
	}

	if h.RD {
		s = s + (1 << 7)
	}

	if h.TC {
		s = s + (1 << 6)
	}

	if h.AA {
		s = s + (1 << 5)
	}

	s = s + (h.OPCODE << 1)
	if h.QR {
		s = s + 1
	}

	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, h.ID)
	binary.Write(&buffer, binary.BigEndian, s)
	binary.Write(&buffer, binary.BigEndian, h.QDCOUNT)
	binary.Write(&buffer, binary.BigEndian, h.ANCOUNT)
	binary.Write(&buffer, binary.BigEndian, h.NSCOUNT)
	binary.Write(&buffer, binary.BigEndian, h.ARCOUNT)

	return buffer.Bytes()

}
func (h *dnsheader) TryFrom(buf []byte) error {

	truetable := []bool{false, true}

	if len(buf) < 12 {
		return errors.New("content is invalid")
	}

	var out = bytes.NewBuffer(buf[:12])

	var s uint16
	binary.Read(out, binary.BigEndian, &h.ID)
	binary.Read(out, binary.BigEndian, &s)
	binary.Read(out, binary.BigEndian, &h.QDCOUNT)
	binary.Read(out, binary.BigEndian, &h.ANCOUNT)
	binary.Read(out, binary.BigEndian, &h.NSCOUNT)
	binary.Read(out, binary.BigEndian, &h.ARCOUNT)

	h.RCODE = (s >> 12) & 0xf
	h.Z = (s >> 9) & 0x7
	h.RA = truetable[((s >> 8) & 0x1)]
	h.RD = truetable[((s >> 7) & 0x1)]
	h.TC = truetable[((s >> 6) & 0x1)]
	h.AA = truetable[((s >> 5) & 0x1)]
	h.OPCODE = (s >> 1) & 0x4
	h.QR = truetable[(s & 0x1)]

	return nil
}

//NewDNSHeader ..
func NewDNSHeader() DNSHeaderBuilder {

	return &dnsheader{}
}
