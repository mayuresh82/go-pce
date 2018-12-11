package pcep

import (
	"bufio"
	"fmt"
	"github.com/golang/glog"
	"net"
	"sync"
	"time"
)

type pccState int

const (
	IDLE        pccState = 1
	TCP_PENDING pccState = 2
	OPEN_WAIT   pccState = 3
	KEEP_WAIT   pccState = 4
	UP          pccState = 5

	OPEN_WAIT_TIMER = 60 * time.Second
	KEEP_WAIT_TIMER = 60 * time.Second
)

// PCC represents a single Path Computation Client
type PCC struct {
	Name string
	KeepAliveTimer,
	DeadTimer time.Duration

	peerSessionID, localSessionID   int
	syncInProgress, syncComplete    bool
	isStateFul, supportsCreate      bool
	state                           pccState
	conn                            *net.TCPConn
	errorChan                       chan error
	keepaliveRecvd, StopSignal      chan bool
	recvMsg, sendMsg, reportRequest chan *PcepMsg
	pcRequests                      chan []*PceRequest
	pcReplies                       chan []*PceReply
	AsyncUpdates, AsyncInit         chan []*LspUpdateRequest
	LspDB                           *lspDb

	sync.Mutex
}

func NewPCC(sid int) *PCC {
	return &PCC{
		localSessionID: sid,
		LspDB:          NewLspDb(),
		StopSignal:     make(chan bool),
		pcRequests:     make(chan []*PceRequest),
		pcReplies:      make(chan []*PceReply),
		AsyncUpdates:   make(chan []*LspUpdateRequest),
		AsyncInit:      make(chan []*LspUpdateRequest),
	}
}

func (p *PCC) GetState() pccState {
	p.Lock()
	defer p.Unlock()
	return p.state
}

func (p *PCC) GetName() string {
	p.Lock()
	defer p.Unlock()
	return p.Name
}

func (p *PCC) GetSessionID() int {
	p.Lock()
	defer p.Unlock()
	return p.localSessionID
}

func (p *PCC) SetName(name string) {
	p.Lock()
	defer p.Unlock()
	p.Name = name
}

func (p *PCC) GetProperties() (bool, bool) {
	p.Lock()
	defer p.Unlock()
	return p.isStateFul, p.supportsCreate
}

// Start servicing the client
func (p *PCC) ServeClient(conn *net.TCPConn) {
	p.conn = conn
	defer p.conn.Close()
	p.recvMsg = make(chan *PcepMsg)
	p.sendMsg = make(chan *PcepMsg)
	p.reportRequest = make(chan *PcepMsg)
	// start data send and receive loops
	go p.readLoop()
	go p.sendLoop()
	// start pce request/reply loop
	go p.handleRequestReply()
	// start state report/ request loop
	go p.parseReportRequest()
	p.keepaliveRecvd = make(chan bool)
	p.state = IDLE
	// wait for pcep connection to come up
	if err := p.openPcepSession(); err != nil {
		glog.Errorf("Failed to establish PCEP session due to %s", err.Error())
		err, _ := err.(PcepError)
		p.sendMsg <- NewErrorMsg(err.ErrorType, err.ErrorValue, []int{})
		return
	}
	// session negotation failed, close tcp connection and start-over
	if p.GetState() != UP {
		close(p.StopSignal)
		return
	}
	glog.V(2).Infof("PCEP session with peer %s is now UP !", p.Name)
	if p.KeepAliveTimer != 0 {
		go p.keepAliveLoop()
	}
	// wait on stop signal or error to terminate session
	select {
	case err := <-p.errorChan:
		glog.Infof("Closing Session with %s due to: %s", p.Name, err.Error())
		close(p.StopSignal)
		return
	case <-p.StopSignal:
		glog.Infof("Exiting Serve() for %s due to stop signal received", p.Name)
		p.state = IDLE
		return
	}
}

// Open a pcep session with the client by sending open and keepalive
func (p *PCC) openPcepSession() error {
	// send open immediately on connect and wait for open
	p.sendMsg <- NewOpenMsg(p.localSessionID)
	p.state = OPEN_WAIT
	openWaitTimer := time.NewTimer(OPEN_WAIT_TIMER)
	var msg *PcepMsg
	select {
	case msg = <-p.recvMsg:
		switch msg.MsgType {
		case TYPE_OPEN:
			if err := p.processOpenMsg(msg); err != nil {
				return err
			} else {
				p.sendMsg <- NewKeepAliveMsg()
				p.state = KEEP_WAIT
				// wait for peer keepalive
				keepWaitTimer := time.NewTimer(KEEP_WAIT_TIMER)
				select {
				case msg = <-p.recvMsg:
					if int(msg.MsgType) != TYPE_KEEPALIVE {
						// this error could be proposing new params, but we dont support negotiation
						glog.Errorf("Peer %s declined our open! , ErrorValue: %d", p.Name, ERR_PCERR_UNACCEPTABLE_PARAMS)
						p.state = IDLE
						return nil
					} else {
						p.state = UP
						// we can now start processing other messages
						go p.processMsg()
						return nil
					}
				case <-keepWaitTimer.C:
					return PcepError{
						msg:        "KeepWait timer expired",
						ErrorType:  ERRTYPE_SESSION_ESTB_FAILURE,
						ErrorValue: ERR_KEEPWAIT_TIMEOUT,
					}
				}
			}
		default:
			glog.Errorf("Expected OPEN from peer %s got : %s", p.Name, MsgTypeToName[int(msg.MsgType)])
			if msg.MsgType == TYPE_ERROR {
				errObj, ok := msg.ObjectList[0].Obj.(*PcepErrorObject)
				var errValue uint8
				if ok {
					errValue = errObj.ErrorValue
				} else {
					errValue = ERR_PCERR_UNACCEPTABLE_PARAMS
				}
				glog.Errorf("Peer %s declined our open! , ErrorValue: %d", p.Name, errValue)
			}
			p.state = IDLE
			return nil
		}
	case <-openWaitTimer.C:
		return PcepError{
			msg:        "OpenWait timer expired",
			ErrorType:  ERRTYPE_SESSION_ESTB_FAILURE,
			ErrorValue: ERR_OPEN_TIMEOUT,
		}
	}
}

// Send pcep messages over the socket to client
func (p *PCC) sendLoop() {
	for {
		select {
		case msg := <-p.sendMsg:
			data := SerializeMessage(msg)
			if _, err := p.conn.Write(data); err != nil {
				glog.V(4).Infof("Failed to write %d bytes to socket: %s", len(data), err.Error())
				continue
			}
		case <-p.StopSignal:
			glog.V(4).Infof("Terminate sendLoop for %s", p.Name)
			return
		}
	}
}

// Read and parse incoming pcep messages from client
func (p *PCC) readLoop() {
	scanner := bufio.NewScanner(p.conn)
	scanner.Split(SplitPcepMessage)
	// read from socket until it is closed
	for scanner.Scan() {
		msg, err := parseMessage(scanner.Bytes())
		if err != nil {
			switch err := err.(type) {
			case error:
				glog.V(4).Infof("Error parsing msg: %s", err.Error())
			case PcepError:
				p.sendMsg <- NewErrorMsg(err.ErrorType, err.ErrorValue, []int{})
			}
			continue
		}
		p.recvMsg <- msg
	}
	var errMsg string
	if err := scanner.Err(); err != nil {
		errMsg = err.Error()
	} else {
		errMsg = "EOF"
	}
	glog.V(4).Infof("Readloop for peer %s closed due to %s", p.Name, errMsg)
	close(p.StopSignal)
}

// Send periodic keepalives, reset deadtime upon receipt of peer keepalives
// and terminate client if deadtimer expires
func (p *PCC) keepAliveLoop() {
	glog.V(2).Infof("Starting Keepalive loop for peer: %s", p.Name)
	keepAliveticker := time.NewTicker(p.KeepAliveTimer)
	deadTimer := time.NewTimer(p.DeadTimer)
	for {
		select {
		case <-keepAliveticker.C:
			glog.V(4).Infof("Sending KeepAlive to %s", p.Name)
			p.sendMsg <- NewKeepAliveMsg()
		case <-p.keepaliveRecvd:
			deadTimer.Reset(p.DeadTimer)
		case <-deadTimer.C:
			glog.V(2).Infof("Dead Timer expired for peer: %s", p.Name)
			p.sendMsg <- NewCloseMsg(CLOSE_DEADTIMER_EXPIRED)
			p.errorChan <- fmt.Errorf("Dead timer expired")
			return
		case <-p.StopSignal:
			glog.V(4).Infof("Terminate keepalive loop for %s", p.Name)
			return
		}
	}
}

// handle lsp signalling requests and replies
func (p *PCC) handleRequestReply() {
	glog.V(2).Infof("Starting Request/Reply loop for peer: %s", p.Name)
	for {
		select {
		case <-p.StopSignal:
			glog.V(4).Infof("Terminate request/reply Loop for %s", p.Name)
			return
		case pcRequests := <-p.pcRequests:
			go func() {
				pcReplies := []*PceReply{}
				for _, req := range pcRequests {
					pcReplies = append(pcReplies, req.ComputePath())
				}
				p.pcReplies <- pcReplies
			}()
		case pcReplies := <-p.pcReplies:
			p.sendMsg <- NewPcReplyMsg(pcReplies)
		}
	}
}

// handle lsp updates for delegated LSPs
func (p *PCC) handleDelegations() {
	for {
		select {
		case <-p.StopSignal:
			glog.V(4).Infof("Terminate delegation Loop for %s", p.Name)
			return
		case updateRequests := <-p.AsyncUpdates:
			p.sendMsg <- NewPcUpdateMsg(updateRequests)
			glog.V(4).Infof("Sending update request for %d Lsps", len(updateRequests))
		case initRequests := <-p.AsyncInit:
			p.sendMsg <- NewPcInitiateMsg(initRequests)
			glog.V(4).Infof("Sending init/delete request for %d Lsps", len(initRequests))
		}
	}
}

// process the open message and set connection params
func (p *PCC) processOpenMsg(msg *PcepMsg) error {
	var errorMsg string
	// some basic error checks
	if int(msg.MsgType) != TYPE_OPEN {
		errorMsg = "Open not received as first message"
	}
	if len(msg.ObjectList) != 1 {
		errorMsg = "ObjectList must have one OPEN only"
	}
	open, ok := msg.ObjectList[0].Obj.(*OpenObject)
	if !ok {
		errorMsg = "Open Msg must have one open object"
	}
	if errorMsg != "" {
		return PcepError{
			msg:        errorMsg,
			ErrorType:  ERRTYPE_SESSION_ESTB_FAILURE,
			ErrorValue: ERR_INVALID_OPEN,
		}
	}
	p.KeepAliveTimer = time.Duration(open.KeepAliveTimer) * time.Second
	p.DeadTimer = time.Duration(open.DeadTimer) * time.Second
	p.peerSessionID = int(open.Sid)
	glog.V(4).Infof("Peer %s open params: k/a: %v, dead: %v, Sid: %d", p.Name, p.KeepAliveTimer, p.DeadTimer, p.peerSessionID)
	// process stateful capability TLV
	if open.StatefulCapability {
		p.isStateFul = true
		glog.V(2).Infof("Peer %s supports Stateful Capabilities", p.Name)
	}
	if open.LspUpdateCapability {
		glog.V(2).Infof("Peer %s supports active LSP updates", p.Name)
	}
	if open.LspCreateCapability {
		p.supportsCreate = true
		glog.V(2).Infof("Peer %s supports LSP creation/deletion", p.Name)
	}
	return nil
}

// process any incoming pcep message
func (p *PCC) processMsg() {
	glog.V(2).Infof("Starting message processing loop for %s", p.Name)
	for {
		msg := <-p.recvMsg
		// any msg may act as a keepalive
		p.keepaliveRecvd <- true
		switch int(msg.MsgType) {
		case TYPE_KEEPALIVE:
			glog.V(4).Infof("Got keepalive from peer %s", p.Name)
		case TYPE_ERROR:
			// we should only be receiving error objects from PCC
			// open-related errors are handled during initiation
			for _, obj := range msg.ObjectList {
				if errObj, ok := obj.Obj.(*PcepErrorObject); ok {
					glog.V(2).Infof("Received error Type %d, error value %d from %s", errObj.ErrorType, errObj.ErrorValue, p.Name)
				}
			}
		case TYPE_NOTIFICATION:
			glog.V(2).Infof("Received notification from %s", p.Name)
		case TYPE_CLOSE:
			if close, ok := msg.ObjectList[0].Obj.(*CloseObject); ok {
				glog.V(2).Infof("Received CLOSE from %s: Reason: %d", p.Name, close.CloseReason)
			}
			p.errorChan <- fmt.Errorf("Peer CLOSED the session")
			// peer will terminate the connection after close
			return
		case TYPE_PCREPORT:
			glog.V(4).Infof("Received State Report from %s", p.Name)
			p.reportRequest <- msg
		case TYPE_PCREQ:
			glog.V(4).Infof("Received Path Computation Request from %s", p.Name)
			p.reportRequest <- msg
		default:
			glog.V(4).Infof("Unsupported MSg Type %d received from %s", int(msg.MsgType), p.Name)
		}
	}
}

// Parse a pcep message into an LSP
func (p *PCC) parseLsp(objects []Object, isRequest bool) *Lsp {
	lsp := NewLsp()
	var (
		removed, sync bool
		err, srpID    int
	)
	for _, obj := range objects {
		switch obj := obj.Obj.(type) {
		case *SRPObject:
			// If srpId != 0, This state report is in response to an earlier PCUpdate
			// mark update request with received srp-id-num as completed or handle error
			srpID = int(obj.SrpId)
		case *LSPObject:
			lsp.PLspID = obj.PLspID
			lsp.Delegated = obj.Delegate
			lsp.DesiredAdminUp = obj.Admin
			lsp.Created = obj.Create
			removed = obj.Remove
			sync = obj.Sync
			lsp.State = lspState(obj.OperState)
			lsp.PathName = obj.SymbolicPathName
			err = obj.LspErrorCode
			lsp.Src = obj.Sender
			lsp.Dst = obj.Endpoint
		case *ExplicitRouteObject:
			lsp.IntendedPath = obj.ExplicitRoutes
		case *EndPointsObject:
			lsp.Src = obj.SourceAddr
			lsp.Dst = obj.DestAddr
		case *BandwidthObject:
			lsp.Attrs.Bandwidth = obj.Bandwidth
		case *LSPAObject:
			lsp.Attrs.SetupPri = int(obj.SetupPri)
			lsp.Attrs.HoldPri = int(obj.HoldPri)
			lsp.Attrs.LocalProtDesired = obj.LocalProtectionDesired
			lsp.Attrs.ExcludeAny = obj.ExcludeAny
		case *MetricObject:
			if obj.Bound {
				lsp.Attrs.MaxMetric = obj.MetricValue
			} else {
				lsp.Attrs.PathMetric = obj.MetricValue
			}
		case *ReportedRouteObject:
			lsp.ReportedPath = obj.ReportedRoutes
		case *IncludeRouteObject:
			lsp.Attrs.IncludeRoutes = obj.IncludeRoutes
		}
	}
	if !isRequest {
		switch {
		case srpID != 0:
			// TODO Send a response back to requestor
			if err != 0 {
				glog.V(4).Infof("Request to %s for srpID %d failed with err: %d", p.Name, srpID, err)
			} else {
				glog.V(4).Infof("Request to %s for srpID %d successful", p.Name, srpID)
				if removed {
					// this is a successful response to an lsp deletion request
					p.LspDB.Remove(lsp.PLspID)
				} else {
					// this is a successful response to an lsp update/create request
					p.LspDB.Add(lsp)
				}
			}
		case removed:
			p.LspDB.Remove(lsp.PLspID)
		case sync:
			if !p.syncInProgress {
				glog.V(2).Infof("Started LSP sync with peer %s", p.Name)
			}
			p.syncInProgress = true
			p.LspDB.Add(lsp)
		case !sync && lsp.PLspID == 0:
			t, d := p.LspDB.GetCount()
			glog.V(2).Infof("Lsp Sync Done with peer %s. Added %d LSPs, %d delegated", p.Name, t, d)
			p.syncComplete = true
			go p.handleDelegations()
		default:
			p.LspDB.Add(lsp)
		}
	}
	return lsp
}

// parse a received PcRpt or PCReq message into an LSP or a request
func (p *PCC) parseReportRequest() {
	for {
		msg := <-p.reportRequest
		boundaries := []int{}
		requests := []*PceRequest{}
		for i, obj := range msg.ObjectList {
			switch obj := obj.Obj.(type) {
			case *SvecObject:
				// ignore svec based grouping for now, add support later
				continue
			case *RpObject:
				request := NewPceRequest()
				request.Priority = obj.Priority
				request.ReOpt = obj.ReOpt
				request.Loose = obj.Loose
				request.RequestID = int(obj.RequestID)
				requests = append(requests, request)
				boundaries = append(boundaries, i)
			case *SRPObject:
				boundaries = append(boundaries, i)
			}
		}
		for i := 0; i < len(boundaries); i++ {
			var objGroup []Object
			if i == len(boundaries)-1 {
				objGroup = msg.ObjectList[boundaries[i]:]
			} else {
				objGroup = msg.ObjectList[boundaries[i]:boundaries[i+1]]
			}
			if msg.MsgType == TYPE_PCREPORT {
				p.parseLsp(objGroup, false)
			} else if msg.MsgType == TYPE_PCREQ {
				requests[i].Lsp = p.parseLsp(objGroup, true)
			}
		}
		if msg.MsgType == TYPE_PCREPORT {
			glog.V(2).Infof("Parsed %d LSPs in message from %s", len(boundaries), p.Name)
		} else if msg.MsgType == TYPE_PCREQ {
			glog.V(2).Infof("Path Computation Message from %s has %d requests", p.Name, len(requests))
			p.pcRequests <- requests
		}
	}
}
