//-----------------------------------------------------------------------------
// Copyright (C) Microsoft. All rights reserved.
// Licensed under the MIT license.
// See LICENSE.txt file in the project root for full license information.
//-----------------------------------------------------------------------------
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/tcpraw"
	"golang.org/x/crypto/pbkdf2"
)

var gCert []byte

func initServer(showUI bool) {
	initServerUI(showUI)
}

func finiServer() {
	ui.fini()
	logFini()
}

func showAcceptedIPVersion() {
	var ipVerString = "ipv4, ipv6"
	if gIPVersion == ethrIPv4 {
		ipVerString = "ipv4"
	} else if gIPVersion == ethrIPv6 {
		ipVerString = "ipv6"
	}
	ui.printMsg("Accepting IP version: %s", ipVerString)
}

func runServer(serverParam ethrServerParam) {
	defer stopStatsTimer()
	initServer(serverParam.showUI)
	startStatsTimer()
	fmt.Println("-----------------------------------------------------------")
	showAcceptedIPVersion()
	if serverParam.protocol == KCP {
		ui.printMsg("Listening on port %d for TCP & KCP", gEthrPort)
		srvrRunKCPServer()
	} else if serverParam.protocol == QUIC {
		ui.printMsg("Listening on port %d for QUIC", gEthrPort)
		srvrRunQUICServer()
	} else {
		ui.printMsg("Listening on port %d for TCP & UDP", gEthrPort)
		srvrRunUDPServer()
	}
	err := srvrRunTCPServer()
	if err != nil {
		finiServer()
		fmt.Printf("Fatal error running TCP server: %v\n", err)
		os.Exit(1)
	}
}

func handshakeWithClient(test *ethrTest, conn net.Conn) (testID EthrTestID, clientParam EthrClientParam, err error) {
	ethrMsg := recvSessionMsg(conn)
	if ethrMsg.Type != EthrSyn {
		ui.printDbg("Failed to receive SYN message from client.")
		err = os.ErrInvalid
		return
	}
	testID = ethrMsg.Syn.TestID
	clientParam = ethrMsg.Syn.ClientParam
	ethrMsg = createAckMsg()
	err = sendSessionMsg(conn, ethrMsg)
	return
}

func srvrRunTCPServer() error {
	l, err := net.Listen(Tcp(), gLocalIP+":"+gEthrPortStr)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		conn, err := l.Accept()
		if err != nil {
			ui.printErr("Error accepting new TCP connection: %v", err)
			continue
		}
		err = conn.(*net.TCPConn).SetWriteBuffer(1024 * 1024 * 4)
		if err != nil {
			ui.printErr("Error tcp SetWriteBuffer: %v", err)
		}

		err = conn.(*net.TCPConn).SetReadBuffer(1024 * 1024 * 4)
		if err != nil {
			ui.printErr("Error tcp SetReadBuffer: %v", err)
		}
		go srvrHandleNewConn(conn, TCP)
	}
}

func srvrHandleNewConn(conn net.Conn, protocol EthrProtocol) {
	defer conn.Close()

	server, port, err := net.SplitHostPort(conn.RemoteAddr().String())
	ethrUnused(server, port)
	if err != nil {
		ui.printDbg("RemoteAddr: Split host port failed: %v", err)
		return
	}
	lserver, lport, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		ui.printDbg("LocalAddr: Split host port failed: %v", err)
		return
	}
	ethrUnused(lserver, lport)
	ui.printDbg("New connection from %v, port %v to %v, port %v", server, port, lserver, lport)

	test, isNew := createOrGetTest(server, protocol, All)
	if test == nil {
		return
	}
	if isNew {
		ui.emitTestHdr()
	}

	isCPSorPing := true
	// For CPS and Ping tests, there is no deterministic way to know when the test starts
	// from the client side and when it ends. This defer function ensures that test is not
	// created/deleted repeatedly by doing a deferred deletion. If another connection
	// comes with-in 2s, then another reference would be taken on existing test object
	// and it won't be deleted by safeDeleteTest call. This also ensures, test header is
	// not printed repeatedly via emitTestHdr.
	// Note: Similar mechanism is used in UDP tests to handle test lifetime as well.
	defer func() {
		if isCPSorPing {
			time.Sleep(2 * time.Second)
		}
		safeDeleteTest(test)
	}()

	// Always increment CPS count and then check if the test is Bandwidth etc. and handle
	// those cases as well.
	atomic.AddUint64(&test.testResult.cps, 1)

	testID, clientParam, err := handshakeWithClient(test, conn)
	if err != nil {
		ui.printDbg("Failed in handshake with the client. Error: %v", err)
		return
	}
	isCPSorPing = false
	if testID.Type == Bandwidth {
		srvrRunBandwidthTest(test, clientParam, conn)
	} else if testID.Type == Latency {
		ui.emitLatencyHdr()
		if clientParam.BufferSizeSend > 1 || clientParam.BufferSizeRecv > 1 {
			srvrRunLatencyTestEx(test, clientParam, conn)
		} else {
			srvrRunLatencyTest(test, clientParam, conn)
		}
	}
}

func srvrRunBandwidthTest(test *ethrTest, clientParam EthrClientParam, conn net.Conn) {
	size := clientParam.BufferSize
	buff := make([]byte, size)
	for i := uint32(0); i < size; i++ {
		buff[i] = byte(i)
	}
	bufferLen := len(buff)
	totalBytesToSend := test.clientParam.BwRate
	sentBytes := uint64(0)
	start, waitTime, bytesToSend := beginThrottle(totalBytesToSend, bufferLen)
	for {
		n := 0
		var err error
		if clientParam.Reverse {
			n, err = conn.Write(buff[:bytesToSend])
		} else {
			n, err = conn.Read(buff)
		}
		if err != nil {
			ui.printDbg("Error sending/receiving data on a connection for bandwidth test: %v", err)
			break
		}
		atomic.AddUint64(&test.testResult.bw, uint64(n))
		if clientParam.Reverse {
			sentBytes += uint64(n)
			start, waitTime, sentBytes, bytesToSend = enforceThrottle(start, waitTime, totalBytesToSend, sentBytes, bufferLen)
		}
	}
}

func srvrRunLatencyTestEx(test *ethrTest, clientParam EthrClientParam, conn net.Conn) {
	clientBytesRecv := make([]byte, int(clientParam.BufferSizeRecv))
	clientBytesSend := make([]byte, int(clientParam.BufferSizeSend))
	for i := uint32(0); i < clientParam.BufferSizeRecv; i++ {
		clientBytesRecv[i] = byte(i)
	}
	rttCount := clientParam.RttCount
	latencyNumbers := make([]time.Duration, rttCount)
	for {
		_, err := io.ReadFull(conn, clientBytesSend)
		if err != nil {
			ui.printDbg("Error receiving data for latency test: %v", err)
			return
		}
		for i := uint32(0); i < rttCount; i++ {
			s1 := time.Now()
			_, err = conn.Write(clientBytesRecv)
			if err != nil {
				ui.printDbg("Error sending data for latency test: %v", err)
				return
			}
			_, err = io.ReadFull(conn, clientBytesSend)
			conn.SetDeadline(time.Now().Add(time.Second * 600))
			if err != nil {
				ui.printDbg("Error receiving data for latency test: %v", err)
				return
			}
			e2 := time.Since(s1)
			latencyNumbers[i] = e2
		}
		sum := int64(0)
		for _, d := range latencyNumbers {
			sum += d.Nanoseconds()
		}
		elapsed := time.Duration(sum / int64(rttCount))
		sort.SliceStable(latencyNumbers, func(i, j int) bool {
			return latencyNumbers[i] < latencyNumbers[j]
		})
		//
		// Special handling for rttCount == 1. This prevents negative index
		// in the latencyNumber index. The other option is to use
		// roundUpToZero() but that is more expensive.
		//
		rttCountFixed := rttCount
		if rttCountFixed == 1 {
			rttCountFixed = 2
		}
		atomic.SwapUint64(&test.testResult.latency, uint64(elapsed.Nanoseconds()))
		avg := elapsed
		min := latencyNumbers[0]
		max := latencyNumbers[rttCount-1]
		p50 := latencyNumbers[((rttCountFixed*50)/100)-1]
		p90 := latencyNumbers[((rttCountFixed*90)/100)-1]
		p95 := latencyNumbers[((rttCountFixed*95)/100)-1]
		p99 := latencyNumbers[((rttCountFixed*99)/100)-1]
		p999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.9)/100)-1)]
		p9999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.99)/100)-1)]
		ui.emitLatencyResults(
			test.session.remoteIP,
			protoToString(test.testID.Protocol),
			avg, min, max, p50, p90, p95, p99, p999, p9999)
	}
}

func srvrRunLatencyTest(test *ethrTest, clientParam EthrClientParam, conn net.Conn) {
	bytes := make([]byte, clientParam.BufferSize)
	rttCount := clientParam.RttCount
	latencyNumbers := make([]time.Duration, rttCount)
	for {
		_, err := io.ReadFull(conn, bytes)
		if err != nil {
			ui.printDbg("Error receiving data for latency test: %v", err)
			return
		}
		for i := uint32(0); i < rttCount; i++ {
			s1 := time.Now()
			_, err = conn.Write(bytes)
			if err != nil {
				ui.printDbg("Error sending data for latency test: %v", err)
				return
			}
			_, err = io.ReadFull(conn, bytes)
			conn.SetDeadline(time.Now().Add(time.Second * 600))
			if err != nil {
				ui.printDbg("Error receiving data for latency test: %v", err)
				return
			}
			e2 := time.Since(s1)
			latencyNumbers[i] = e2
		}
		sum := int64(0)
		for _, d := range latencyNumbers {
			sum += d.Nanoseconds()
		}
		elapsed := time.Duration(sum / int64(rttCount))
		sort.SliceStable(latencyNumbers, func(i, j int) bool {
			return latencyNumbers[i] < latencyNumbers[j]
		})
		//
		// Special handling for rttCount == 1. This prevents negative index
		// in the latencyNumber index. The other option is to use
		// roundUpToZero() but that is more expensive.
		//
		rttCountFixed := rttCount
		if rttCountFixed == 1 {
			rttCountFixed = 2
		}
		atomic.SwapUint64(&test.testResult.latency, uint64(elapsed.Nanoseconds()))
		avg := elapsed
		min := latencyNumbers[0]
		max := latencyNumbers[rttCount-1]
		p50 := latencyNumbers[((rttCountFixed*50)/100)-1]
		p90 := latencyNumbers[((rttCountFixed*90)/100)-1]
		p95 := latencyNumbers[((rttCountFixed*95)/100)-1]
		p99 := latencyNumbers[((rttCountFixed*99)/100)-1]
		p999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.9)/100)-1)]
		p9999 := latencyNumbers[uint64(((float64(rttCountFixed)*99.99)/100)-1)]
		ui.emitLatencyResults(
			test.session.remoteIP,
			protoToString(test.testID.Protocol),
			avg, min, max, p50, p90, p95, p99, p999, p9999)
	}
}

func srvrRunUDPServer() error {
	udpAddr, err := net.ResolveUDPAddr(Udp(), gLocalIP+":"+gEthrPortStr)
	if err != nil {
		ui.printDbg("Unable to resolve UDP address: %v", err)
		return err
	}
	l, err := net.ListenUDP(Udp(), udpAddr)
	if err != nil {
		ui.printDbg("Error listening on %s for UDP pkt/s tests: %v", gEthrPortStr, err)
		return err
	}
	// Set socket buffer to 4MB per CPU so we can queue 4MB per CPU in case Ethr is not
	// able to keep up temporarily.
	err = l.SetReadBuffer(runtime.NumCPU() * 4 * 1024 * 1024)
	if err != nil {
		ui.printDbg("Failed to set ReadBuffer on UDP socket: %v", err)
	}
	//
	// We use NumCPU here instead of NumThreads passed from client. The
	// reason is that for UDP, there is no connection, so all packets come
	// on same CPU, so it isn't clear if there are any benefits to running
	// more threads than NumCPU(). TODO: Evaluate this in future.
	//
	for i := 0; i < runtime.NumCPU(); i++ {
		go srvrRunUDPPacketHandler(l)
	}
	return nil
}

func srvrRunKCPServer() error {
	config := KCPConfig{}
	err := parseKCPJSONConfig(&config, "kcp.json")
	if err != nil {
		ui.printErr("parse kcp config error:", err)
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

	ui.printDbg("key:%v", config.Key)
	ui.printDbg("encryption:%v", config.Crypt)
	ui.printDbg("mode:%v", config.Mode)
	ui.printDbg("mtu:%v", config.MTU)
	ui.printDbg("sndwnd:%v rcvwnd:%v", config.SndWnd, config.RcvWnd)
	ui.printDbg("datashard:%v parityshard:%v", config.DataShard, config.ParityShard)
	ui.printDbg("dscp:%v", config.DSCP)
	ui.printDbg("acknodelay:%v", config.AckNodelay)
	ui.printDbg("nodelay:%v interval:%v resend:%v nc:%v", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	ui.printDbg("sockbuf:%v", config.SockBuf)
	ui.printDbg("tcp:%v", config.TCP)
	ui.printDbg("streammode:%v", config.StreamMode)

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

	if config.TCP { // tcp dual stack
		conn, err := tcpraw.Listen("tcp", gLocalIP+":"+gEthrPortStr)
		if err != nil {
			ui.printErr("tcpraw.Listen: %v", err)
		}
		lis, err := kcp.ServeConn(block, config.DataShard, config.ParityShard, conn)
		if err != nil {
			ui.printErr("kcp.ServeConn: %v", err)
		}
		go srvrRunKCPPacketHandler(lis, config)
	}

	lis, err := kcp.ListenWithOptions(gLocalIP+":"+gEthrPortStr, block, config.DataShard, config.ParityShard)
	if err != nil {
		ui.printErr("kcp.ListenWithOptions: %v", err)
	}
	go srvrRunKCPPacketHandler(lis, config)
	return nil
}

func srvrRunUDPPacketHandler(conn *net.UDPConn) {
	// This local map aids in efficiency to look up a test based on client's IP
	// address. We could use createOrGetTest but that takes a global lock.
	tests := make(map[string]*ethrTest)
	// For UDP, allocate buffer that can accomodate largest UDP datagram.
	readBuffer := make([]byte, 64*1024)
	n, remoteIP, err := 0, new(net.UDPAddr), error(nil)

	// This function handles UDP tests that came from clients that are no longer
	// sending any traffic. This is poor man's garbage collection to ensure the
	// server doesn't end up printing dormant client related statistics as UDP
	// has no reliable way to detect if client is active or not.
	go func() {
		for {
			time.Sleep(100 * time.Millisecond)
			for k, v := range tests {
				ui.printDbg("Found Test from server: %v, time: %v", k, v.lastAccess)
				// At 200ms of no activity, mark the test in-active so stats stop
				// printing.
				if time.Since(v.lastAccess) > (200 * time.Millisecond) {
					v.isDormant = true
				}
				// At 2s of no activity, delete the test by assuming that client
				// has stopped.
				if time.Since(v.lastAccess) > (2 * time.Second) {
					ui.printDbg("Deleting UDP test from server: %v, lastAccess: %v", k, v.lastAccess)
					safeDeleteTest(v)
					delete(tests, k)
				}
			}
		}
	}()
	for err == nil {
		n, remoteIP, err = conn.ReadFromUDP(readBuffer)
		if err != nil {
			ui.printDbg("Error receiving data from UDP for bandwidth test: %v", err)
			continue
		}
		ethrUnused(remoteIP)
		ethrUnused(n)
		server, port, _ := net.SplitHostPort(remoteIP.String())
		test, found := tests[server]
		if !found {
			var isNew bool
			test, isNew = createOrGetTest(server, UDP, All)
			if test != nil {
				tests[server] = test
			}
			if isNew {
				ui.printDbg("Creating UDP test from server: %v, lastAccess: %v", server, time.Now())
				ui.emitTestHdr()
			}
		}
		if test != nil {
			test.isDormant = false
			test.lastAccess = time.Now()
			atomic.AddUint64(&test.testResult.pps, 1)
			atomic.AddUint64(&test.testResult.bw, uint64(n))
		} else {
			ui.printDbg("Unable to create test for UDP traffic on port %s from %s port %s", gEthrPortStr, server, port)
		}
	}
}

func srvrRunKCPPacketHandler(listener *kcp.Listener, config KCPConfig) {
	if err := listener.SetDSCP(config.DSCP); err != nil {
		ui.printErr("kcp SetDSCP:%v", err)
	}
	if err := listener.SetReadBuffer(config.SockBuf); err != nil {
		ui.printErr("kcp SetReadBuffer:%v", err)
	}
	if err := listener.SetWriteBuffer(config.SockBuf); err != nil {
		ui.printErr("kcp SetWriteBuffer:%v", err)
	}

	for {
		s, err := listener.AcceptKCP()
		if err != nil {
			ui.printDbg("AcceptKCP error: %v", err)
		}
		s.SetStreamMode(config.StreamMode)
		s.SetWriteDelay(false)
		s.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		s.SetMtu(config.MTU)
		s.SetWindowSize(config.SndWnd, config.RcvWnd)
		s.SetACKNoDelay(config.AckNodelay)
		s.SetDeadline(time.Now().Add(time.Second * 600))

		go srvrHandleNewConn(s, KCP)
		//go printKCPStat()
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

func srvrRunQUICServer() error {
	//github.com/lucas-clemente/quic-go@v0.21.1/interface.go
	config := &quic.Config{
		HandshakeIdleTimeout:           time.Second * 30,
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
	l, err := quic.ListenAddr(gLocalIP+":"+gEthrPortStr, generateTLSConfig(), config)
	if err != nil {
		return err
	}
	defer l.Close()
	for {
		sess, err := l.Accept(context.Background())
		if err != nil {
			return err
		}

		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			ui.printErr("sess.AcceptStream error:%v", err)
			return err
		}
		conn := QuicStreamConn{
			stream: stream,
			local:  sess.LocalAddr(),
			remote: sess.RemoteAddr(),
		}
		go srvrHandleNewConn(conn, QUIC)
	}
}
