//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"bufio"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/pkg/errors"
	quic "github.com/quic-go/quic-go"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
	"golang.org/x/crypto/pbkdf2"
)

var gLocalIP = ""
var gEthrPort = uint16(8888)
var gEthrPortStr = ""
var gClientPort = uint16(0)
var gTOS = uint8(0)
var gTTL = uint8(0)

const (
	UNO  = 1
	KILO = 1000
	MEGA = 1000 * 1000
	GIGA = 1000 * 1000 * 1000
	TERA = 1000 * 1000 * 1000 * 1000
)

func numberToUnit(num uint64) string {
	unit := ""
	value := float64(num)

	switch {
	case num >= TERA:
		unit = "T"
		value = value / TERA
	case num >= GIGA:
		unit = "G"
		value = value / GIGA
	case num >= MEGA:
		unit = "M"
		value = value / MEGA
	case num >= KILO:
		unit = "K"
		value = value / KILO
	}

	result := strconv.FormatFloat(value, 'f', 2, 64)
	result = strings.TrimSuffix(result, ".00")
	return result + unit
}

func numberToUnitEx(num uint64) string {
	return fmt.Sprintf("%d", num)
}

func unitToNumber(s string) uint64 {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	i := strings.IndexFunc(s, unicode.IsLetter)

	if i == -1 {
		bytes, err := strconv.ParseFloat(s, 64)
		if err != nil || bytes <= 0 {
			return 0
		}
		return uint64(bytes)
	}

	bytesString, multiple := s[:i], s[i:]
	bytes, err := strconv.ParseFloat(bytesString, 64)
	if err != nil || bytes <= 0 {
		return 0
	}

	switch multiple {
	case "T", "TB", "TIB":
		return uint64(bytes * TERA)
	case "G", "GB", "GIB":
		return uint64(bytes * GIGA)
	case "M", "MB", "MIB":
		return uint64(bytes * MEGA)
	case "K", "KB", "KIB":
		return uint64(bytes * KILO)
	case "B":
		return uint64(bytes)
	default:
		return 0
	}
}

func bytesToRate(bytes uint64) string {
	bits := bytes * 8
	result := numberToUnitEx(bits)
	return result
}

func cpsToString(cps uint64) string {
	result := numberToUnit(cps)
	return result
}

func ppsToString(pps uint64) string {
	result := numberToUnit(pps)
	return result
}

func testToString(testType EthrTestType) string {
	switch testType {
	case Bandwidth:
		return "Bandwidth"
	case Cps:
		return "Connections/s"
	case Pps:
		return "Packets/s"
	case Latency:
		return "Latency"
	case Ping:
		return "Ping"
	case TraceRoute:
		return "TraceRoute"
	case MyTraceRoute:
		return "MyTraceRoute"
	default:
		return "Invalid"
	}
}

func durationToString(d time.Duration) string {
	if d < 0 {
		return d.String()
	}
	ud := uint64(d)
	val := float64(ud)
	unit := ""
	if ud < uint64(60*time.Second) {
		switch {
		case ud < uint64(time.Microsecond):
			unit = "ns"
		case ud < uint64(time.Millisecond):
			val = val / 1000
			unit = "us"
		case ud < uint64(time.Second):
			val = val / (1000 * 1000)
			unit = "ms"
		default:
			val = val / (1000 * 1000 * 1000)
			unit = "s"
		}

		result := strconv.FormatFloat(val, 'f', 1, 64)
		return result + unit
	}

	return d.String()
}

func durationToStringEx(d time.Duration) string {
	if d < 0 {
		return d.String()
	}
	ud := uint64(d)
	val := float64(ud)
	if ud < uint64(3600*time.Second) {
		val = val / (1000 * 1000)
		result := strconv.FormatFloat(val, 'f', 3, 64)
		return result
	}

	return d.String()
}

func protoToString(proto EthrProtocol) string {
	switch proto {
	case TCP:
		return "TCP"
	case UDP:
		return "UDP"
	case ICMP:
		return "ICMP"
	case KCP:
		return "KCP"
	case QUIC:
		return "QUIC"
	}
	return ""
}

func Tcp() string {
	switch gIPVersion {
	case ethrIPv4:
		return "tcp4"
	case ethrIPv6:
		return "tcp6"
	}
	return "tcp"
}

func Udp() string {
	switch gIPVersion {
	case ethrIPv4:
		return "udp4"
	case ethrIPv6:
		return "udp6"
	}
	return "udp"
}

func Icmp() string {
	switch gIPVersion {
	case ethrIPv6:
		return "ip6:ipv6-icmp"
	default:
		return "ip4:icmp"
	}
}

func IcmpProto() int {
	if gIPVersion == ethrIPv6 {
		return ICMPv6
	}
	return ICMPv4
}

func ethrUnused(vals ...interface{}) {
	for _, val := range vals {
		_ = val
	}
}

func splitString(longString string, maxLen int) []string {
	splits := []string{}

	var l, r int
	for l, r = 0, maxLen; r < len(longString); l, r = r, r+maxLen {
		for !utf8.RuneStart(longString[r]) {
			r--
		}
		splits = append(splits, longString[l:r])
	}
	splits = append(splits, longString[l:])
	return splits
}

func max(x, y uint64) uint64 {
	if x < y {
		return y
	}
	return x
}

func toString(n int) string {
	return fmt.Sprintf("%d", n)
}

func toInt(s string) int {
	res, err := strconv.Atoi(s)
	if err != nil {
		ui.printDbg("Error in string conversion: %v", err)
		return 0
	}
	return res
}

func truncateStringFromStart(str string, num int) string {
	s := str
	l := len(str)
	if l > num {
		if num > 3 {
			s = "..." + str[l-num+3:l]
		} else {
			s = str[l-num : l]
		}
	}
	return s
}

func truncateStringFromEnd(str string, num int) string {
	s := str
	l := len(str)
	if l > num {
		if num > 3 {
			s = str[0:num] + "..."
		} else {
			s = str[0:num]
		}
	}
	return s
}

func roundUpToZero(n int64) int64 {
	y := n >> 63
	return (n ^ y) - y
}

func getFd(conn net.Conn) uintptr {
	var fd uintptr
	var rc syscall.RawConn
	var err error
	switch ct := conn.(type) {
	case *net.TCPConn:
		rc, err = ct.SyscallConn()
		if err != nil {
			return 0
		}
	case *net.UDPConn:
		rc, err = ct.SyscallConn()
		if err != nil {
			return 0
		}
	case *kcp.UDPSession:
		return uintptr(conn.(*kcp.UDPSession).GetConv())
	default:
		return 0
	}
	fn := func(s uintptr) {
		fd = s
	}
	rc.Control(fn)
	return fd
}

type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func SleepUntilNextWholeSecond() {
	t0 := time.Now()
	t1 := t0.Add(time.Second)
	res := t1.Round(time.Second)
	time.Sleep(time.Until(res))
}

func ethrSetTTL(fd uintptr, ttl int) {
	if ttl == 0 {
		return
	}
	if gIPVersion == ethrIPv4 {
		setSockOptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
	} else {
		setSockOptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
	}
}

func ethrSetTOS(fd uintptr, tos int) {
	if tos == 0 {
		return
	}
	if gIPVersion == ethrIPv4 {
		setSockOptInt(fd, syscall.IPPROTO_IP, syscall.IP_TOS, tos)
	} else {
		SetTClass(fd, tos)
	}
}

func ethrDial(p EthrProtocol, dialAddr string) (conn net.Conn, err error) {
	return ethrDialEx(p, dialAddr, gLocalIP, gClientPort, int(gTTL), int(gTOS))
}

func ethrDialInc(p EthrProtocol, dialAddr string, inc uint16) (conn net.Conn, err error) {
	if gClientPort != 0 {
		return ethrDialEx(p, dialAddr, gLocalIP, gClientPort+inc, int(gTTL), int(gTOS))
	} else {
		return ethrDial(p, dialAddr)
	}
}

func ethrDialAll(p EthrProtocol, dialAddr string) (conn net.Conn, err error) {
	return ethrDialEx(p, dialAddr, gLocalIP, 0, int(gTTL), int(gTOS))
}

func ethrDialKCP(addr string) (*kcp.UDPSession, error) {
	config := KCPConfig{}
	err := parseKCPJSONConfig(&config, "kcp.json")
	if err != nil {
		ui.printErr("parse kcp config error:", err)
	}
	pass := pbkdf2.Key([]byte(config.Key), []byte("kcp-go"), 4096, 32, sha1.New)
	var block kcp.BlockCrypt
	switch config.Crypt {
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	case "aes":
		block, _ = kcp.NewAESBlockCrypt(pass)
	default:

	}

	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}
	var sess *kcp.UDPSession
	if config.TCP {
		conn, e := tcpraw.Dial("tcp", addr)
		if e != nil {
			return nil, errors.Wrap(err, "tcpraw.Dial()")
		}
		sess, err = kcp.NewConn(addr, block, config.DataShard, config.ParityShard, conn)
	} else {
		ui.printDbg("kcp.DialWithOptions addr=%v config.DataShard=%v config.ParityShard=%v block=%v", addr, config.DataShard, config.ParityShard, block)
		sess, err = kcp.DialWithOptions(addr, block, config.DataShard, config.ParityShard)
	}

	if err != nil {
		return nil, errors.Wrap(err, "kcp.NewConn or kcp.DialWithOptions")
	}

	ui.printDbg("kcp session set config=%+v", config)
	sess.SetStreamMode(config.StreamMode)
	sess.SetWriteDelay(false)
	sess.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	sess.SetWindowSize(config.SndWnd, config.RcvWnd)
	sess.SetMtu(config.MTU)
	sess.SetACKNoDelay(config.AckNodelay)

	if err := sess.SetDSCP(config.DSCP); err != nil {
		ui.printErr("SetDSCP:%v", err)
	}
	if err := sess.SetReadBuffer(config.SockBuf); err != nil {
		ui.printErr("SetReadBuffer:%v", err)
	}
	if err := sess.SetWriteBuffer(config.SockBuf); err != nil {
		ui.printErr("SetWriteBuffer:", err)
	}

	return sess, err
}

type bufferedWriteCloser struct {
	*bufio.Writer
	io.Closer
}

// NewBufferedWriteCloser creates an io.WriteCloser from a bufio.Writer and an io.Closer
func NewBufferedWriteCloser(writer *bufio.Writer, closer io.Closer) io.WriteCloser {
	return &bufferedWriteCloser{
		Writer: writer,
		Closer: closer,
	}
}

func (h bufferedWriteCloser) Close() error {
	if err := h.Writer.Flush(); err != nil {
		return err
	}
	return h.Closer.Close()
}

func GetSSLKeyLog() (io.WriteCloser, error) {
	filename := os.Getenv("SSLKEYLOGFILE")
	fmt.Println("filename ssl =", filename)
	if len(filename) == 0 {
		return nil, nil
	}
	f, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func ethrDialQUIC(addr string) (net.Conn, error) {
	keyLog, _ := GetSSLKeyLog()
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
		KeyLogWriter:       keyLog,
	}
	//github.com/lucas-clemente/quic-go@v0.21.1/interface.go
	config := &quic.Config{
		HandshakeIdleTimeout:           time.Second * 10,
		MaxIdleTimeout:                 time.Minute,
		InitialStreamReceiveWindow:     1048576,
		MaxStreamReceiveWindow:         10485760,
		InitialConnectionReceiveWindow: 1048576,
		MaxConnectionReceiveWindow:     104857600,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          1000,
		KeepAlivePeriod:                5 * time.Second,
		// Tracer: qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
		// filename := fmt.Sprintf("client_%x.qlog", connID)
		// fmt.Println("filename=", filename)
		// f, err := os.Create(filename)
		// if err != nil {
		// log.Fatal(err)
		// }
		// log.Printf("Creating qlog file %s.\n", filename)
		// return NewBufferedWriteCloser(bufio.NewWriter(f), f)
		// }),
	}
	session, err := quic.DialAddr(addr, tlsConf, config)
	if err != nil {
		ui.printErr("quic.DialAddr error:%v", err)
		session.CloseWithError(0, "quic.DialAddr error")
		return nil, err
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		ui.printErr("Error dialing connection: %v", err)
		stream.Close()
		return nil, err
	}

	conn := QuicStreamConn{
		stream: stream,
		local:  session.LocalAddr(),
		remote: session.RemoteAddr(),
	}
	return conn, err
}

func ethrDialEx(p EthrProtocol, dialAddr, localIP string, localPortNum uint16, ttl int, tos int) (conn net.Conn, err error) {
	if p == KCP {
		ui.printDbg("ethrDialKCP %v", dialAddr)
		return ethrDialKCP(dialAddr)
	}
	if p == QUIC {
		ui.printDbg("ethrDialQUIC %v", dialAddr)
		return ethrDialQUIC(dialAddr)
	}
	localAddr := fmt.Sprintf("%v:%v", localIP, localPortNum)
	var la net.Addr
	network := Tcp()
	if p == TCP {
		la, err = net.ResolveTCPAddr(network, localAddr)
	} else if p == UDP {
		network = Udp()
		la, err = net.ResolveUDPAddr(network, localAddr)
	} else {
		ui.printDbg("Only TCP or UDP are allowed in ethrDial")
		err = os.ErrInvalid
		return
	}
	if err != nil {
		ui.printErr("Unable to resolve TCP or UDP address. Error: %v", err)
		return
	}
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				ethrSetTTL(fd, ttl)
				ethrSetTOS(fd, tos)
			})
		},
	}
	dialer.LocalAddr = la
	dialer.Timeout = time.Second * 60
	conn, err = dialer.Dial(network, dialAddr)
	if err != nil {
		ui.printDbg("ethrTCPDial Error: %v", err)
	} else {
		tcpconn, ok := conn.(*net.TCPConn)
		if ok {
			err := tcpconn.SetLinger(0)
			if err != nil {
				ui.printDbg("Failed to set tcp SetLinger 0: %v", err)
			}
			err = tcpconn.SetReadBuffer(1024 * 1024 * 4)
			if err != nil {
				ui.printDbg("Failed to tcpconn.SetReadBuffer: %v", err)
			}
			err = tcpconn.SetWriteBuffer(1024 * 1024 * 4)
			if err != nil {
				ui.printDbg("Failed to tcpconn.SetWriteBuffer: %v", err)
			}
		}
		udpconn, ok := conn.(*net.UDPConn)
		if ok {
			err = udpconn.SetWriteBuffer(4 * 1024 * 1024)
			if err != nil {
				ui.printDbg("Failed to set ReadBuffer on UDP socket: %v", err)
			}
		}
	}
	return
}

func ethrLookupIP(server string) (net.IPAddr, string, error) {
	var ipAddr net.IPAddr
	var ipStr string

	ip := net.ParseIP(server)
	if ip != nil {
		ipAddr.IP = ip
		ipStr = server
		return ipAddr, ipStr, nil
	}

	ips, err := net.LookupIP(server)
	if err != nil {
		ui.printErr("Failed to lookup IP address for the server: %v. Error: %v", server, err)
		return ipAddr, ipStr, err
	}
	for _, ip := range ips {
		if gIPVersion == ethrIPAny || (gIPVersion == ethrIPv4 && ip.To4() != nil) || (gIPVersion == ethrIPv6 && ip.To16() != nil) {
			ipAddr.IP = ip
			ipStr = ip.String()
			ui.printDbg("Resolved server: %v to IP address: %v\n", server, ip)
			return ipAddr, ipStr, nil
		}
	}
	ui.printErr("Unable to resolve the given server: %v to an IP address.", server)
	return ipAddr, ipStr, os.ErrNotExist
}

// This is a workaround to ensure we generate traffic at certain rate
// and stats are printed correctly. We ensure that current interval lasts
// 100ms after stats are printed, not perfect but workable.
func beginThrottle(totalBytesToSend uint64, bufferLen int) (start time.Time, waitTime time.Duration, bytesToSend int) {
	start = time.Now()
	waitTime = time.Until(lastStatsTime.Add(time.Second + 50*time.Millisecond))
	bytesToSend = bufferLen
	if totalBytesToSend > 0 && totalBytesToSend < uint64(bufferLen) {
		bytesToSend = int(totalBytesToSend)
	}
	return
}

func enforceThrottle(s time.Time, wt time.Duration, totalBytesToSend, oldSentBytes uint64, bufferLen int) (start time.Time, waitTime time.Duration, newSentBytes uint64, bytesToSend int) {
	start = s
	waitTime = wt
	newSentBytes = oldSentBytes
	bytesToSend = bufferLen
	if totalBytesToSend > 0 {
		remainingBytes := totalBytesToSend - oldSentBytes
		if remainingBytes > 0 {
			if remainingBytes < uint64(bufferLen) {
				bytesToSend = int(remainingBytes)
			}
		} else {
			timeTaken := time.Since(s)
			if timeTaken < wt {
				time.Sleep(wt - timeTaken)
			}
			start = time.Now()
			waitTime = time.Until(lastStatsTime.Add(time.Second + 50*time.Millisecond))
			newSentBytes = 0
			if totalBytesToSend < uint64(bufferLen) {
				bytesToSend = int(totalBytesToSend)
			}
		}
	}
	return
}

func printKCPStat() {
	fmt.Printf("====================printKCPStat=====================\n")
	fmt.Printf("kcp.DefaultSnmp=%+v\n", kcp.DefaultSnmp)
}
