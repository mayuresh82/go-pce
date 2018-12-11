package pcep

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	PCEP_VERSION   = 1
	COMMON_HDR_LEN = 4

	// PCEP Message Types
	TYPE_OPEN         = 1
	TYPE_KEEPALIVE    = 2
	TYPE_PCREQ        = 3
	TYPE_PCREP        = 4
	TYPE_NOTIFICATION = 5
	TYPE_ERROR        = 6
	TYPE_CLOSE        = 7
	TYPE_PCREPORT     = 10
	TYPE_PCUPDATE     = 11
	TYPE_PCINITIATE   = 12

	KEEPALIVE_TIMER = 30
)

var MsgTypeToName map[int]string = map[int]string{
	TYPE_OPEN:         "OPEN",
	TYPE_KEEPALIVE:    "KEEPALIVE",
	TYPE_PCREQ:        "PCREQ",
	TYPE_PCREP:        "PCREP",
	TYPE_NOTIFICATION: "NOTIFICATION",
	TYPE_ERROR:        "ERROR",
	TYPE_CLOSE:        "CLOSE",
	TYPE_PCREPORT:     "PCREPORT",
	TYPE_PCUPDATE:     "PCUPDATE",
	TYPE_PCINITIATE:   "PCINITIATE",
}

type CommonHeader struct {
	VersionFlags,
	MsgType uint8
	MsgLen uint16
}

func NewCommonHeader(mType, mLength int) *CommonHeader {
	return &CommonHeader{
		VersionFlags: uint8(PCEP_VERSION << 5),
		MsgType:      uint8(mType),
		MsgLen:       uint16(COMMON_HDR_LEN + mLength),
	}
}

func (h *CommonHeader) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, h)
	if h.VersionFlags>>5 != PCEP_VERSION {
		err = fmt.Errorf("CommonHdr.Parse: Version must be %d", PCEP_VERSION)
	}
	return
}

func (h CommonHeader) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, h)
	return buf.Bytes()
}

type Object struct {
	ObjClass int
	Obj      PcepObject
}

// a Pcep Message is a list of Pcep Objects
type PcepMsg struct {
	MsgType    int
	ObjectList []Object
}

func NewPcepMsg(msgType int) *PcepMsg {
	return &PcepMsg{MsgType: msgType}
}

// Open message is used to signal initial session params and contains a open object.
func NewOpenMsg(sid int) *PcepMsg {
	objList := []Object{
		Object{
			ObjClass: OC_OPEN,
			Obj: &OpenObject{
				VersionFlags:        uint8(PCEP_VERSION << 5),
				KeepAliveTimer:      uint8(KEEPALIVE_TIMER),
				DeadTimer:           uint8(KEEPALIVE_TIMER * 4),
				Sid:                 uint8(sid),
				StatefulCapability:  true,
				LspUpdateCapability: true,
				LspCreateCapability: true,
			},
		},
	}
	return &PcepMsg{MsgType: TYPE_OPEN, ObjectList: objList}
}

// KeepAlive is just a common header with no objects
func NewKeepAliveMsg() *PcepMsg {
	return &PcepMsg{
		MsgType:    TYPE_KEEPALIVE,
		ObjectList: []Object{},
	}
}

// Close message is used to signal a session closure and contains a close object.
func NewCloseMsg(closeReason int) *PcepMsg {
	objList := []Object{
		Object{
			ObjClass: OC_CLOSE,
			Obj: &CloseObject{
				CloseReason: closeReason,
			},
		},
	}
	return &PcepMsg{MsgType: TYPE_CLOSE, ObjectList: objList}
}

// Error msg is used to signal an error and contains an Error object
func NewErrorMsg(errType, errValue int, reqIDs []int) *PcepMsg {
	objList := []Object{}
	for _, reqID := range reqIDs {
		objList = append(objList, Object{
			ObjClass: OC_RP,
			Obj: &RpObject{
				Priority:  0,
				ReOpt:     false,
				BiDir:     false,
				Loose:     false,
				RequestID: uint32(reqID)},
		})
	}
	objList = append(objList, Object{
		ObjClass: OC_PCEPERROR,
		Obj:      &PcepErrorObject{ErrorType: uint8(errType), ErrorValue: uint8(errValue)},
	})
	return &PcepMsg{MsgType: TYPE_ERROR, ObjectList: objList}
}

// getLspAttrObjects returns a slice of lsp attribute objects required for lsp
// signalling.
func getLspAttrObjects(lsp *Lsp) []Object {
	objList := []Object{}
	// insert ERO (intended/computed-path)
	explicitRoutes := []Ero{}
	for _, hop := range lsp.ComputedPath {
		explicitRoutes = append(explicitRoutes, hop)
	}
	objList = append(objList, Object{
		ObjClass: OC_ERO,
		Obj:      &ExplicitRouteObject{ExplicitRoutes: explicitRoutes}})
	attrs := lsp.Attrs
	// insert LSPA, BW, Metric objects
	objList = append(objList, []Object{
		Object{
			ObjClass: OC_LSPA,
			Obj: &LSPAObject{SetupPri: uint8(attrs.SetupPri), HoldPri: uint8(attrs.HoldPri),
				ExcludeAny: attrs.ExcludeAny, LocalProtectionDesired: attrs.LocalProtDesired},
		},
		Object{
			ObjClass: OC_BANDWIDTH,
			Obj:      &BandwidthObject{Bandwidth: attrs.Bandwidth},
		},
		Object{
			ObjClass: OC_METRIC,
			Obj: &MetricObject{
				MetricType:  METRIC_TE,
				Bound:       false,
				Computed:    false,
				MetricValue: attrs.PathMetric},
		},
	}...)
	// insert IRO
	if len(attrs.IncludeRoutes) > 0 {
		includeRoutes := []Ero{}
		for _, hop := range attrs.IncludeRoutes {
			includeRoutes = append(includeRoutes, hop)
		}
		objList = append(objList, Object{
			ObjClass: OC_IRO,
			Obj:      &IncludeRouteObject{IncludeRoutes: includeRoutes}})
	}
	return objList
}

// a PCReply Message is used to reply to a request for a new path comupation
//    <PCRep Message> ::= <Common Header>
//                        <response-list>
//
//    where:
//
//       <response-list>::=<response>[<response-list>]
//
//       <response>::=<RP>
//                   [<NO-PATH>]
//                   [<attribute-list>]
//                   [<path-list>]
//
//       <path-list>::=<path>[<path-list>]
//
//       <path>::= <ERO><attribute-list>
//
//    where:
//
//     <attribute-list>::=[<LSPA>]
//                        [<BANDWIDTH>]
//                        [<metric-list>]
//                        [<IRO>]
//
//     <metric-list>::=<METRIC>[<metric-list>]
func NewPcReplyMsg(replies []*PceReply) *PcepMsg {
	objList := []Object{}
	for _, reply := range replies {
		// insert RP object
		objList = append(objList, Object{
			ObjClass: OC_RP,
			Obj:      &RpObject{Priority: 0, ReOpt: false, BiDir: false, Loose: false, RequestID: uint32(reply.RequestID)},
		})
		lsp := reply.Lsp
		// insert LSP object
		objList = append(objList, Object{
			ObjClass: OC_LSP,
			Obj:      &LSPObject{PLspID: lsp.PLspID, Delegate: lsp.Delegated, Admin: true},
		})
		// if no paths available, insert NoPath
		if len(lsp.ComputedPath) == 0 {
			objList = append(objList, Object{
				ObjClass: OC_NOPATH,
				Obj: &NoPathObject{
					NatureofIssue: NOPATH_CONSTRAINT_FAILED,
					CFlag:         0, // we dont support sending the failing constraints
				},
			})
			continue
		}
		// insert ERO-Attrs
		objList = append(objList, getLspAttrObjects(lsp)...)
	}
	return &PcepMsg{MsgType: TYPE_PCREP, ObjectList: objList}
}

// a PcUpdate Message is used to update LSP path attributes and has the below format
//      <PCUpd Message> ::= <Common Header>
//                          <update-request-list>
//   Where:
//
//      <update-request-list> ::= <update-request>[<update-request-list>]
//
//      <update-request> ::= <SRP>
//                           <LSP>
//                           <path>
//   Where:
//      <path>::= <intended_path><attribute-list>
//
//   Where:
//      <intended_path> is represented by the ERO objec
func NewPcUpdateMsg(requests []*LspUpdateRequest) *PcepMsg {
	objList := []Object{}
	for _, request := range requests {
		// insert SRP Object
		objList = append(objList, Object{
			ObjClass: OC_SRP,
			Obj:      &SRPObject{SrpId: uint32(request.SrpId)},
		})
		// insert LSP Object
		objList = append(objList, Object{
			ObjClass: OC_LSP,
			Obj:      &LSPObject{PLspID: request.Lsp.PLspID, Delegate: request.Lsp.Delegated, Admin: true},
		})
		// insert ERO-Attrs
		objList = append(objList, getLspAttrObjects(request.Lsp)...)
	}
	return &PcepMsg{MsgType: TYPE_PCUPDATE, ObjectList: objList}
}

// a PcInitiate Message is used to signal or delete LSPs and has the below format
//      <PCInitiate Message> ::= <Common Header>
//                               <PCE-initiated-lsp-list>
//   Where:
//
//      <PCE-initiated-lsp-list> ::= <PCE-initiated-lsp-request>
//                                   [<PCE-initiated-lsp-list>]
//
//      <PCE-initiated-lsp-request> ::= (<PCE-initiated-lsp-instantiation>|
//                                       <PCE-initiated-lsp-deletion>)
//
//      <PCE-initiated-lsp-instantiation> ::= <SRP>
//                                            <LSP>
//                                            <END-POINTS>
//                                            <ERO>
//                                            [<attribute-list>]
//
//      <PCE-initiated-lsp-deletion> ::= <SRP>
//                                       <LSP>
func NewPcInitiateMsg(requests []*LspUpdateRequest) *PcepMsg {
	objList := []Object{}
	for _, request := range requests {
		// insert SRP Object
		srp := &SRPObject{SrpId: uint32(request.SrpId)}
		if request.Delete {
			srp.Remove = true
		}
		objList = append(objList, Object{
			ObjClass: OC_SRP,
			Obj:      srp,
		})
		// insert LSP Object
		objList = append(objList, Object{
			ObjClass: OC_LSP,
			Obj: &LSPObject{
				PLspID:           request.Lsp.PLspID,
				Delegate:         request.Lsp.Delegated,
				Admin:            true,
				SymbolicPathName: request.Lsp.PathName},
		})
		if request.Delete {
			continue
		}
		// insert EP object
		oType := ENDPOINT_IPV4
		len := 8
		if request.Lsp.Src.To4() == nil {
			oType = ENDPOINT_IPV6
			len = 32
		}
		ep := &EndPointsObject{
			Hdr:        NewCommonObjectHeader(OC_ENDPOINTS, oType, len),
			SourceAddr: request.Lsp.Src,
			DestAddr:   request.Lsp.Dst,
		}
		objList = append(objList, Object{
			ObjClass: OC_ENDPOINTS,
			Obj:      ep,
		})
		// insert ERO-Attrs
		objList = append(objList, getLspAttrObjects(request.Lsp)...)
	}
	return &PcepMsg{MsgType: TYPE_PCINITIATE, ObjectList: objList}
}
