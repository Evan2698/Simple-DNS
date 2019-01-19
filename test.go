package main

import (
	"bytes"
	"fmt"
	"net"

	"github.com/Evan2698/Simple-DNS/dns"
)

func main() {

	/*conn, err := net.Dial("udp", "114.114.114.114:53")
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	defer conn.Close()*/

	/*	var name = ParseDomainName("www.baidu.com.")
		msg := dnsmessage.Message{
			Header: dnsmessage.Header{Response: true, Authoritative: true, ID: 0xffff},
			Questions: []dnsmessage.Question{
				{
					Name:  mustNewName(string(name)),
					Type:  dnsmessage.TypeAAAA,
					Class: dnsmessage.ClassINET,
				},
			},
		}NewDNSQuery

		_, err = msg.Pack()
		if err != nil {
			fmt.Println("")
		}

		var (
			dns_header   DNSHeader
			dns_question DNSQuery
		)

		//填充dns首部
		dns_header.ID = 0xFFFF
		dns_header.SetFlag(0, 0, 0, 0, 1, 0, 0)
		dns_header.QuestionCount = 1
		dns_header.AnswerRRs = 0
		dns_header.AuthorityRRs = 0
		dns_header.AdditionalRRs = 0

		dns_question.QuestionType = 1 //IPv4
		dns_question.QuestionClass = 1

		var buffer bytes.Buffer

		binary.Write(&buffer, binary.BigEndian, dns_header)
		binary.Write(&buffer, binary.BigEndian, ParseDomainName("www.baidu.com"))
		binary.Write(&buffer, binary.BigEndian, dns_question)
		fmt.Println(buffer.Bytes())

		conn.Write(buffer.Bytes())

		fmt.Println(len(buffer.Bytes()))
		fmt.Println("-------------send-------------")
		fmt.Println(buffer.Bytes())
		fmt.Println("------------------------------")

		l := make([]byte, 1024)

		n, err := conn.Read(l)
		if err != nil || n < 0 {

			fmt.Print(err)
			return
		}
		fmt.Println(n)

		fmt.Println("-------------recv-------------")
		fmt.Println(l[:n])
		fmt.Println("------------------------------")

		tcpcon, err := net.Dial("tcp", "114.114.114.114:53")
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		defer tcpcon.Close()

		var sl uint16
		sl = uint16(len(buffer.Bytes()))

		var out bytes.Buffer
		binary.Write(&out, binary.BigEndian, sl)

		var sendout []byte

		w := append(sendout, out.Bytes()...)
		q := append(w, buffer.Bytes()...)

		fmt.Println(len(q))
		fmt.Println("----------tcp send-------------")
		fmt.Println(q)
		fmt.Println("-------------------------------")
		tcpcon.Write(q)

		n, err = tcpcon.Read(l)
		if err != nil || n < 0 {

			fmt.Print(err)
			return
		}

		fmt.Println("---------tcp recv-------------")
		fmt.Println(l[:n])
		fmt.Println("------------------------------")*/

	/*builder := dns.NewDNSHeader()
	builder.SetQDCount(1)
	builder.SetID(0x5454)
	builder.SetRD(true)

	qs := dns.NewDNSQuery()
	qs.SetName("www.baidu.com")
	qs.SetType(1)
	qs.SetClass(1)

	var out bytes.Buffer
	binary.Write(&out, binary.BigEndian, builder.Pack())
	binary.Write(&out, binary.BigEndian, qs.Pack())

	fmt.Println(out.Bytes(), "======>", len(out.Bytes()))

	conn.Write(out.Bytes())

	rec := make([]byte, 1024)

	n, err := conn.Read(rec)

	fmt.Println(err)
	fmt.Println(rec[:n], "--->", n)

	pa := rec[:n]

	rheader := dns.NewDNSHeader()
	rheader.TryFrom(pa)

	fmt.Println("qdcount: ", rheader.GetQDCount())
	fmt.Println("ANcount: ", rheader.GetANCount())

	fmt.Println("QS:", pa[12:])

	rs := dns.NewDNSQuery()
	if rheader.GetQDCount() == 1 {
		rs.TryFrom(pa[12:])
		fmt.Println(rs.FormatName())
	}

	fmt.Println("QS size: ", rs.GetSize())

	offset := 12 + rs.GetSize()

	fmt.Println("ANFULL:", pa[offset:])

	var i uint16
	for i = 0; i < rheader.GetANCount(); i++ {
		as := dns.NewDNSAnswer()

		er := as.TryFrom(pa[offset:])
		fmt.Println(er)
		fmt.Println(as.FormatName(pa), "<--------------------->", as.FormatR(pa))

		offset = offset + as.GetSize()

	}*/

	pc, err := net.ListenPacket("udp", "127.0.0.1:6053")
	if err != nil {
		fmt.Println("can not listen on 127.0.0.1:6053 ")
		return
	}
	defer pc.Close()

	for {
		buffer := make([]byte, 1024)
		n, addr, err := pc.ReadFrom(buffer)
		if err != nil {
			fmt.Println(err)

		}

		datag := buffer[:n]

		//1. header
		header := dns.NewDNSHeader()
		header.TryFrom(datag)
		header.SetQR(true)
		header.SetRA(true)
		header.SetRD(true)
		//header.SetTC(true)
		header.SetOPCode(0)
		header.SetRCODE(0)
		header.SetANCount(1)
		header.SetQDCount(1)
		header.SetARCount(1)

		// 2. question
		qs := dns.NewDNSQuery()
		qs.TryFrom(datag[12:])

		out := bytes.NewBuffer(header.Pack())
		out.Write(qs.Pack())

		//3. answer
		as := &dns.AnswerDNS{}
		as.Name = []byte{0xc0, 0x0c}
		as.Type = 1
		as.Class = 1
		as.TTL = 242
		as.RDLen = 4
		as.RDATA = []byte{0x1, 0x1, 0x1, 0x1}

		ok := (dns.Answer)(as)
		out.Write(ok.Pack())

		//4. EDNS
		rs := &dns.AnswerDNS{}
		rs.Name = []byte{0x00}
		rs.Type = 41
		rs.Class = 0
		rs.TTL = 0
		rs.RDLen = 0
		rs.RDATA = nil
		ok = (dns.Answer)(rs)
		out.Write(ok.Pack())
		pc.WriteTo(out.Bytes(), addr)
	}

}
