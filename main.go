package main

import (
	"flag"
	"github.com/golang/glog"
	"google.golang.org/grpc"
	"net"
	"pce/pcep"
	"strconv"
	"time"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/testdata"
)

var (
	serverAddr = flag.String("addr", "[::]:14841", "Addr for grpc server")
	tls        = flag.Bool("tls", false, "Connection uses TLS if true, else plain TCP")
	certFile   = flag.String("certFile", "", "The TLS cert file")
	keyFile    = flag.String("keyFile", "", "The TLS key file")
)

const (
	pcepPort           = 4189
	connectRetryTimer  = 60 * time.Second
	stateCheckInterval = 5 * time.Second
)

var (
	sessions      map[string]*pcep.PCC = make(map[string]*pcep.PCC)
	baseSessionId                      = 1
	globalLspDb   *pcep.GlobalLspDb    = pcep.NewGlobalLspDb()
)

func newLocalSessionID() int {
	sid := baseSessionId
	baseSessionId = sid + 1
	return sid
}

// periodically check and remove stale clients from the db
func maintainSessionDB() {
	checkInterval := time.NewTicker(stateCheckInterval)
	for {
		for pccName, pcc := range sessions {
			if pcc.GetState() == pcep.IDLE {
				glog.Infof("Peer %s went Idle, removing from state DB", pccName)
				globalLspDb.RemovePcc(pccName)
				delete(sessions, pccName)
			}
		}
		<-checkInterval.C
	}
}

// Start listening on the pcep port for clients and service them in different
// goroutines
func startListen() {
	laddr := net.JoinHostPort("::", strconv.FormatInt(int64(pcepPort), 10))
	listenAddr, err := net.ResolveTCPAddr("tcp", laddr)
	if err != nil {
		glog.Fatalf("Cannot resolve local: %s\n", err.Error())
	}
	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		glog.Fatalf("Cannot listen on address: %v", listenAddr)
	}
	for {
		conn, err := ln.AcceptTCP()
		if err != nil {
			glog.Errorf("Cannot connect to remote: %s\n", err.Error())
			time.Sleep(time.Duration(connectRetryTimer))
			continue
		}
		glog.Infof("Connected to remote : %v", conn.RemoteAddr())
		pcc := pcep.NewPCC(newLocalSessionID())
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		pcc.SetName(host)
		sessions[pcc.Name] = pcc
		globalLspDb.AddPcc(pcc)
		go pcc.ServeClient(conn)
	}
}

func main() {
	flag.Parse()
	glog.Infof("Starting Pcep listener on port %d", pcepPort)
	go maintainSessionDB()
	go startListen()
	lis, err := net.Listen("tcp", *serverAddr)
	if err != nil {
		glog.Fatalf("failed to listen: %v", err)
	}
	var opts []grpc.ServerOption
	if *tls {
		if *certFile == "" {
			*certFile = testdata.Path("server1.pem")
		}
		if *keyFile == "" {
			*keyFile = testdata.Path("server1.key")
		}
		creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
		if err != nil {
			glog.Fatalf("Failed to generate credentials %v", err)
		}
		opts = []grpc.ServerOption{grpc.Creds(creds)}
	}
	glog.Infof("Starting GRPC server on %v", *serverAddr)
	grpcServer := grpc.NewServer(opts...)
	pcep.RegisterPceServiceServer(grpcServer, &PceServer{})
	grpcServer.Serve(lis)
}
