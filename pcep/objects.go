package pcep

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"

	"github.com/golang/glog"
)

// Reference: RFC 5440, D Stateful, D Pce-Initiated

const (
	COMMON_OBJECT_HDR_LEN = 4

	// Object Classes
	OC_OPEN         = 1
	OC_RP           = 2
	OC_NOPATH       = 3
	OC_ENDPOINTS    = 4
	OC_BANDWIDTH    = 5
	OC_METRIC       = 6
	OC_ERO          = 7
	OC_RRO          = 8
	OC_LSPA         = 9
	OC_IRO          = 10
	OC_SVEC         = 11
	OC_NOTIFICATION = 12
	OC_PCEPERROR    = 13
	OC_LB           = 14 // not supported
	OC_CLOSE        = 15
	OC_LSP          = 32
	OC_SRP          = 33

	// nopath NI
	NOPATH_CONSTRAINT_FAILED = 0
	NOPATH_PCECHAIN_BROKEN   = 1

	// nopath object types
	NOPATH_PCE_DOWN     = 1
	NOPATH_UNKNOWN_DEST = 2
	NOPATH_UNKNOWN_SRC  = 3

	// Metric Types
	METRIC_IGP  = 1
	METRIC_TE   = 2
	METRIC_HOPS = 3

	// endpoint object tyoes
	ENDPOINT_IPV4 = 1
	ENDPOINT_IPV6 = 2

	// ERO usbobject types
	SUBOBJECT_IPV4  = 1
	SUBOBJECT_IPV6  = 2
	SUBOBJECT_LABEL = 3

	// notification object types
	NOTIF_PENDING_REQUEST_CANCELLED = 1
	NOTIF_PCE_OVERLOADED            = 2

	// error object types
	ERRTYPE_SESSION_ESTB_FAILURE  = 1
	ERRTYPE_CAP_UNSUPPORTED       = 2
	ERRTYPE_UNKNOWN_OBJECT        = 3
	ERRTYPE_UNSUPPORTED_OBJECT    = 4
	ERRTYPE_POLICY_VIOLATION      = 5
	ERRTYPE_MANDATORY_OBJ_MISSING = 6
	ERRTYPE_SYC_PCREQ_MISSING     = 7
	ERRTYPE_UNKNOWN_REQ_REF       = 8
	ERRTYPE_SESSION_ALREADY_UP    = 9
	ERRTYPE_INVALID_OBJECT        = 10
	ERRTYPE_INVALID_OPERATION     = 19
	ERRTYPE_STATE_SYNCH_ERROR     = 20
	ERRTYPE_LSP_INSTANTIATION     = 24

	// error object values for ErrType 1
	ERR_INVALID_OPEN                   = 1
	ERR_OPEN_TIMEOUT                   = 2
	ERR_UNACCEPTABLE_NONEG_PARAMS      = 3
	ERR_UNACCEPTABLE_NEG_PARAMS        = 4
	ERR_SECONDOPEN_UNACCEPTABLE_PARAMS = 5
	ERR_PCERR_UNACCEPTABLE_PARAMS      = 6
	ERR_KEEPWAIT_TIMEOUT               = 7

	// ErrType  3
	ERR_UNRECOGNIZED_OBJECT_CLASS = 1
	ERR_UNRECOGNIZED_OJBJECT_TYPE = 2

	// ErrType 4
	ERR_UNSUPPORTED_OBJECT_CLASS = 1
	ERR_UNSUPPORTED_OBJECT_TYPE  = 2

	// ErrType 5
	ERR_METRIC_CBIT_SET = 1
	ERR_RP_OBIT_SET     = 2

	// ErrType 6
	ERR_RP_MISSING                 = 1
	ERR_RRO_MISSING_REOPT          = 2
	ERR_LSP_MISSING                = 8
	ERR_ERO_MISSING                = 9
	ERR_SRP_MISSING                = 10
	ERR_LSP_ID_TLV_MISSING         = 11
	ERR_SYMBOLIC_PNAME_TLV_MISSING = 14

	// ErrType 10
	ERR_PFLAG_NOTSET = 1

	// ErrType 19
	ERR_UPDATE_NONDELEGATED_LSP  = 1
	ERR_UPDATE_NON_STATEFUL_PCE  = 2
	ERR_UPDATE_UNKNOWN_PLSP_ID   = 3
	ERR_REPORT_NON_STATEFUL_PCE  = 5
	ERR_PCINIT_LSP_LIMIT_REACHED = 6
	ERR_LSP_NOT_PCINIT           = 9

	// ErrType 20
	ERR_REPORT_PROCESSING_ERROR = 1
	ERR_STATE_SYNC_ERROR        = 5

	// ErrType 24
	ERR_INITPARAMS_UNACCEPTABLE = 1
	ERR_INTERNAL                = 2
	ERR_SIGNALLING              = 3

	// Close object reasons
	CLOSE_UNKNOWN                            = 1
	CLOSE_DEADTIMER_EXPIRED                  = 2
	CLOSE_MALFORMED_MSG_RECVD                = 3
	CLOSE_UNKNOWN_REQ_THRESHOLD_EXCEEDED     = 4
	CLOSE_UNSUPPORTED_REQ_THRESHOLD_EXCEEDED = 5

	// TLV Types
	TLV_TYPE_STATEFUL_CAPABILITY  = 16
	TLV_TYPE_SYMBOLIC_PATH_NAME   = 17
	TLV_TYPE_IPV4_LSP_IDENTIFIERS = 18
	TLV_TYPE_IPV6_LSP_IDENTIFIERS = 19
	TLV_TYPE_LSP_ERROR_CODE       = 20

	// LSP Update Error Codes
	LSP_ERR_UNKNWON                        = 1
	LSP_ERR_PCE_LIMIT_REACHED              = 2
	LSP_ERR_PENDING_REQUEST_THRES_EXCEEDED = 3
	LSP_ERR_UNACCEPTABLE_PARAMS            = 4
	LSP_ERR_INTERNAL                       = 5
	LSP_ERR_ADMIN_DOWN                     = 6
	LSP_ERR_PREEMPTED                      = 7
	LSP_ERR_RSVP_ERR                       = 8
)

var UnsupportedObjects []int = []int{OC_LB}

type PcepObject interface {
	Parse([]byte) error
	Serialize() []byte
}

func NewObjectByClass(class int) PcepObject {
	switch class {
	case OC_OPEN:
		return &OpenObject{}
	case OC_RP:
		return &RpObject{}
	case OC_NOPATH:
		return &NoPathObject{}
	case OC_ENDPOINTS:
		return &EndPointsObject{}
	case OC_BANDWIDTH:
		return &BandwidthObject{}
	case OC_METRIC:
		return &MetricObject{}
	case OC_ERO:
		return &ExplicitRouteObject{}
	case OC_RRO:
		return &ReportedRouteObject{}
	case OC_LSPA:
		return &LSPAObject{}
	case OC_IRO:
		return &IncludeRouteObject{}
	case OC_SVEC:
		return &SvecObject{}
	case OC_NOTIFICATION:
		return &NotificationObject{}
	case OC_PCEPERROR:
		return &PcepErrorObject{}
	case OC_CLOSE:
		return &CloseObject{}
	case OC_LSP:
		return &LSPObject{}
	case OC_SRP:
		return &SRPObject{}
	}
	return nil
}

type TLV struct {
	Type, Length uint16
	Value        interface{}
}

type PcepError struct {
	msg string
	ErrorType,
	ErrorValue int
}

func (e PcepError) Error() string {
	return e.msg
}

func makeIP(data []byte) net.IP {
	ip := make(net.IP, len(data))
	copy(ip, data)
	return ip
}

// A PCEP object carried within a PCEP message consists of one or more
// 32-bit words with a common header
type CommonObjectHeader struct {
	ObjectClass      uint8
	ObjectType       int
	ProcRule, Ignore bool
	Length           uint16
}

func NewCommonObjectHeader(oClass, oType, length int) *CommonObjectHeader {
	return &CommonObjectHeader{
		ObjectClass: uint8(oClass),
		ObjectType:  oType,
		ProcRule:    true,
		Ignore:      false,
		Length:      uint16(COMMON_OBJECT_HDR_LEN + length),
	}
}

func (h *CommonObjectHeader) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &h.ObjectClass)
	next, _ := buf.ReadByte()
	h.ObjectType = int(uint8(next) >> 4)
	for _, unsup := range UnsupportedObjects {
		if int(h.ObjectClass) == unsup {
			err = PcepError{
				msg:        "CommonObjectHeader.Parse: Unsupported Object",
				ErrorType:  ERRTYPE_UNSUPPORTED_OBJECT,
				ErrorValue: ERR_UNSUPPORTED_OBJECT_CLASS,
			}
			return
		}
	}
	if int(h.ObjectClass) < OC_OPEN || int(h.ObjectType) > OC_SRP {
		err = PcepError{
			msg:        "CommonObjectHeader.Parse: Unsupported Object",
			ErrorType:  ERRTYPE_UNSUPPORTED_OBJECT,
			ErrorValue: ERR_UNSUPPORTED_OBJECT_CLASS,
		}
		return
	}
	if 1<<1&next != 0 {
		h.ProcRule = true
	}
	if 1&next != 0 {
		h.Ignore = true
	}
	var length uint16
	binary.Read(buf, binary.BigEndian, &length)
	h.Length = length
	return
}

func (h CommonObjectHeader) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, h.ObjectClass)
	var p, i int
	if h.ProcRule {
		p = 1
	} else if h.Ignore {
		i = 1
	}
	next := uint8(h.ObjectType<<4 | p<<1 | i)
	binary.Write(buf, binary.BigEndian, next)
	binary.Write(buf, binary.BigEndian, h.Length)
	return buf.Bytes()
}

// The OPEN object MUST be present in each Open message and MAY be
// present in a PCErr message.  There MUST be only one OPEN object per
// Open or PCErr message.
//
// The OPEN object contains a set of fields used to specify the PCEP
// version, Keepalive frequency, DeadTimer, and PCEP session ID, along
// with various flags.
type OpenObject struct {
	VersionFlags,
	KeepAliveTimer,
	DeadTimer,
	Sid uint8
	StatefulCapability,
	LspUpdateCapability,
	LspCreateCapability bool
}

func (o *OpenObject) Parse(data []byte) (err error) {
	//  process only first 4 bytes, no optional TLVs defined as of RFC5540
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &o.VersionFlags)
	binary.Read(buf, binary.BigEndian, &o.KeepAliveTimer)
	binary.Read(buf, binary.BigEndian, &o.DeadTimer)
	binary.Read(buf, binary.BigEndian, &o.Sid)
	if o.VersionFlags>>5 != PCEP_VERSION {
		err = fmt.Errorf("OpenObject.Parse: Version must be %d", PCEP_VERSION)
	}
	// read any TLVs. Only support stateful_cap_tlv for now
	var tType, tLen uint16
	for buf.Len() > 0 {
		binary.Read(buf, binary.BigEndian, &tType)
		binary.Read(buf, binary.BigEndian, &tLen)
		if int(tType) == TLV_TYPE_STATEFUL_CAPABILITY {
			var value uint32
			binary.Read(buf, binary.BigEndian, &value)
			o.StatefulCapability = true
			o.LspUpdateCapability = 1&value != 0
			o.LspCreateCapability = 1<<2&value != 0
		} else {
			buf.Next(int(tLen))
		}
	}
	return
}

func (o OpenObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, o.VersionFlags)
	binary.Write(buf, binary.BigEndian, o.KeepAliveTimer)
	binary.Write(buf, binary.BigEndian, o.DeadTimer)
	binary.Write(buf, binary.BigEndian, o.Sid)
	if o.StatefulCapability {
		// insert tlv
		binary.Write(buf, binary.BigEndian, uint16(TLV_TYPE_STATEFUL_CAPABILITY))
		binary.Write(buf, binary.BigEndian, uint16(4))
		var u, c int
		if o.LspUpdateCapability {
			u = 1
		}
		if o.LspCreateCapability {
			c = 1
		}
		flags := uint32(c<<2 | u)
		fmt.Println(flags)
		binary.Write(buf, binary.BigEndian, flags)
	}
	return buf.Bytes()
}

// The RP (Request Parameters) object MUST be carried within each PCReq
// and PCRep messages and MAY be carried within PCNtf and PCErr
// messages.  The RP object is used to specify various characteristics
// of the path computation request.
type RpObject struct {
	Priority int
	ReOpt,
	BiDir,
	Loose bool
	RequestID uint32
}

func (o *RpObject) Parse(data []byte) (err error) {
	// process only first 8 bytes, no optional TLVs defined as of RFC5540
	buf := bytes.NewBuffer(data)
	// first 3 bytes are undefined
	buf.Next(3)
	flags, _ := buf.ReadByte()
	o.Priority = int(flags & 7)
	o.Loose = 1<<5&flags != 0
	o.BiDir = 1<<4&flags != 0
	o.ReOpt = 1<<3&flags != 0
	var requestID uint32
	binary.Read(buf, binary.BigEndian, &requestID)
	if requestID == 0 {
		err = PcepError{
			msg:       "RpObject.Parse: Unknown Request Reference",
			ErrorType: ERRTYPE_UNKNOWN_REQ_REF,
		}
		return
	}
	o.RequestID = requestID
	return
}

func (o RpObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	var l, b, r int
	if o.Loose {
		l = 1
	}
	if o.BiDir {
		b = 1
	}
	if o.ReOpt {
		r = 1
	}
	flags := uint8(l<<6 | b<<5 | r<<4 | o.Priority)
	for i := 0; i <= 3; i++ {
		binary.Write(buf, binary.BigEndian, uint8(0))
	}
	binary.Write(buf, binary.BigEndian, flags)
	binary.Write(buf, binary.BigEndian, o.RequestID)
	return buf.Bytes()
}

// The NO-PATH object is used in PCRep messages in response to an
// unsuccessful path computation request (the PCE could not find a path
// satisfying the set of constraints).  When a PCE cannot find a path
// satisfying a set of constraints, it MUST include a NO-PATH object in
// the PCRep message.
type NoPathObject struct {
	NatureofIssue uint8
	CFlag         int
	NoPathVector  *TLV
}

func (o *NoPathObject) Parse(data []byte) (err error) {
	return fmt.Errorf("NoPathObject Does not support Parsing")
}

func (o NoPathObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, o.NatureofIssue)
	flags := uint16(o.CFlag << 0x0e)
	binary.Write(buf, binary.BigEndian, flags)
	binary.Write(buf, binary.BigEndian, uint8(0))
	if o.NoPathVector != nil {
		binary.Write(buf, binary.BigEndian, o.NoPathVector.Type)
		binary.Write(buf, binary.BigEndian, o.NoPathVector.Length)
		binary.Write(buf, binary.BigEndian, o.NoPathVector.Value)
	}
	return buf.Bytes()
}

// The END-POINTS object is used in a PCReq message to specify the
// source IP address and the destination IP address of the path for
// which a path computation is requested.
type EndPointsObject struct {
	// we require info from the header to parse this one
	Hdr                  *CommonObjectHeader
	SourceAddr, DestAddr net.IP
}

func (o *EndPointsObject) Parse(data []byte) (err error) {
	// EndPoints object cannot have the P flag cleared
	if !o.Hdr.ProcRule {
		err = PcepError{
			msg:        "EndPointObject.Parse: P Flag Cleared",
			ErrorType:  ERRTYPE_INVALID_OBJECT,
			ErrorValue: ERR_PFLAG_NOTSET,
		}
		return
	}
	buf := bytes.NewBuffer(data)
	var tmp []byte
	if o.Hdr.ObjectType == ENDPOINT_IPV4 {
		o.SourceAddr = makeIP(buf.Next(4))
		o.DestAddr = makeIP(buf.Next(4))
		copy(o.DestAddr, tmp)
	} else if o.Hdr.ObjectType == ENDPOINT_IPV6 {
		o.SourceAddr = makeIP(buf.Next(16))
		o.DestAddr = makeIP(buf.Next(16))
	} else {
		err = PcepError{
			msg:        "EndPointObject.Parse: Unsupported ObjectType",
			ErrorType:  ERRTYPE_UNSUPPORTED_OBJECT,
			ErrorValue: ERR_UNSUPPORTED_OBJECT_TYPE,
		}
	}
	return
}

func (o EndPointsObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	if o.Hdr.ObjectType == ENDPOINT_IPV4 {
		buf.Write(o.SourceAddr[12:])
		buf.Write(o.DestAddr[12:])
	} else if o.Hdr.ObjectType == ENDPOINT_IPV6 {
		buf.Write(o.SourceAddr)
		buf.Write(o.DestAddr)
	}
	return buf.Bytes()
}

// The BANDWIDTH object is used to specify the requested bandwidth for a
// TE LSP.
// If the requested bandwidth is equal to 0, the BANDWIDTH object is
// optional.  Conversely, if the requested bandwidth is not equal to 0,
// the PCReq message MUST contain a BANDWIDTH object.
type BandwidthObject struct {
	// the BW in IEEE 754 format in bytes per second
	Bandwidth float32
}

func (o *BandwidthObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	var bw uint32
	binary.Read(buf, binary.BigEndian, &bw)
	o.Bandwidth = math.Float32frombits(bw)
	return
}

func (o BandwidthObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	bwBits := math.Float32bits(o.Bandwidth)
	binary.Write(buf, binary.BigEndian, bwBits)
	return buf.Bytes()
}

// In a PCReq message, a PCC MAY insert one or more METRIC objects:
//
//    o  To indicate the metric that MUST be optimized by the path
//       computation algorithm (IGP metric, TE metric, hop counts).
//       Currently, three metrics are defined: the IGP cost, the TE metric
//       (see [RFC3785]), and the number of hops traversed by a TE LSP.
//
//    o  To indicate a bound on the path cost that MUST NOT be exceeded for
//       the path to be considered as acceptable by the PCC.
//
//    In a PCRep message, the METRIC object MAY be inserted so as to
//    provide the cost for the computed path.  It MAY also be inserted
//    within a PCRep with the NO-PATH object to indicate that the metric
//    constraint could not be satisfied.
type MetricObject struct {
	MetricType      int
	Bound, Computed bool
	// metric in IEEE 754 format
	MetricValue float32
}

func (o *MetricObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(2)
	flags, _ := buf.ReadByte()
	o.Bound = 1<<1&flags != 0
	o.Computed = 1&flags != 0
	mType, _ := buf.ReadByte()
	o.MetricType = int(mType)
	var metricValue uint32
	binary.Read(buf, binary.BigEndian, &metricValue)
	o.MetricValue = math.Float32frombits(metricValue)
	return
}

func (o MetricObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(0))
	var c, b int
	if o.Computed {
		c = 1
	}
	if o.Bound {
		b = 1
	}
	metricValue := math.Float32bits(o.MetricValue)
	flags := uint8(c<<1 | b)
	binary.Write(buf, binary.BigEndian, flags)
	binary.Write(buf, binary.BigEndian, uint8(o.MetricType))
	binary.Write(buf, binary.BigEndian, metricValue)
	return buf.Bytes()
}

type Ero struct {
	Loose bool
	Type  int
	Addr  *net.IPNet
}

func (e Ero) String() string {
	return fmt.Sprintf("[%v %v]", e.Loose, e.Addr)
}

type Rro struct {
	Type                               int
	Addr                               *net.IPNet
	RecordedLabel                      uint32
	LocalProtAvailable, LocalProtInUse bool
}

func (r Rro) String() string {
	return fmt.Sprintf("[%v %d %v %v]", r.Addr, r.RecordedLabel, r.LocalProtAvailable, r.LocalProtInUse)
}

func parseEroSubObjects(data []byte) []Ero {
	buf := bytes.NewBuffer(data)
	var subObjects []Ero
	for buf.Len() > 0 {
		var (
			soType int
			soLen  uint8
			loose  bool
		)
		first, _ := buf.ReadByte()
		loose = 1<<7&first != 0
		soType = int(first & 127)
		binary.Read(buf, binary.BigEndian, &soLen)
		var (
			ip            net.IP
			mask          net.IPMask
			maskLen, resv uint8
		)
		switch soType {
		case SUBOBJECT_IPV4:
			ip = makeIP(buf.Next(4))
			binary.Read(buf, binary.BigEndian, &maskLen)
			mask = net.CIDRMask(int(maskLen), 32)
		case SUBOBJECT_IPV6:
			ip = makeIP(buf.Next(16))
			binary.Read(buf, binary.BigEndian, &maskLen)
			mask = net.CIDRMask(int(maskLen), 128)
		default:
			glog.V(4).Infof("Ero.Parse: UnsupportedSubObject Type %d", soType)
			buf.Next(int(soLen))
			continue
		}
		ero := Ero{Loose: loose, Type: soType, Addr: &net.IPNet{IP: ip, Mask: mask}}
		binary.Read(buf, binary.BigEndian, &resv)
		subObjects = append(subObjects, ero)
	}
	return subObjects
}

// The ERO is used to encode the path of a TE LSP through the network.
// The ERO is carried within a PCRep message to provide the computed TE
// LSP if the path computation was successful.
type ExplicitRouteObject struct {
	// we support ERO that only contains PrefixSubObjects
	ExplicitRoutes []Ero
}

func (o *ExplicitRouteObject) Parse(data []byte) (err error) {
	o.ExplicitRoutes = parseEroSubObjects(data)
	return
}

func (o ExplicitRouteObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	for _, obj := range o.ExplicitRoutes {
		var (
			lbit   int
			length uint8
		)
		if obj.Loose {
			lbit = 1
		}
		lType := uint8(lbit<<7 | obj.Type)
		binary.Write(buf, binary.BigEndian, lType)
		var ip []byte
		switch obj.Type {
		case SUBOBJECT_IPV4:
			length = 8
			// IP is always 16 bytes long so for v4 we need to extract the last 4 bytes
			ip = obj.Addr.IP[len(obj.Addr.IP)-4:]
		case SUBOBJECT_IPV6:
			length = 20
			ip = obj.Addr.IP
		}
		binary.Write(buf, binary.BigEndian, length)
		binary.Write(buf, binary.BigEndian, ip)
		maskLen, _ := obj.Addr.Mask.Size()
		binary.Write(buf, binary.BigEndian, uint8(maskLen))
		binary.Write(buf, binary.BigEndian, uint8(0))
	}
	return buf.Bytes()
}

// The RRO is carried within a PCReq or PCRpt message so as to report
// the route followed by a TE LSP for which a reoptimization is desired.
// same as Record Route Object
type ReportedRouteObject struct {
	ReportedRoutes []Rro
}

func (o *ReportedRouteObject) Parse(data []byte) (err error) {
	var (
		subObjects []Rro
		counter    int
		soLen      uint8
	)
	buf := bytes.NewBuffer(data)
	for buf.Len() > 0 {
		first, _ := buf.ReadByte()
		soType := int(first)
		binary.Read(buf, binary.BigEndian, &soLen)
		var (
			ip             net.IP
			mask           net.IPMask
			maskLen, flags uint8
		)
		switch soType {
		case SUBOBJECT_IPV4:
			ip = makeIP(buf.Next(4))
			binary.Read(buf, binary.BigEndian, &maskLen)
			mask = net.CIDRMask(int(maskLen), 32)
			rro := Rro{Type: soType, Addr: &net.IPNet{IP: ip, Mask: mask}}
			binary.Read(buf, binary.BigEndian, &flags)
			rro.LocalProtAvailable = 1&flags != 0
			rro.LocalProtInUse = 1<<1&flags != 0
			subObjects = append(subObjects, rro)
		case SUBOBJECT_IPV6:
			ip = makeIP(buf.Next(16))
			binary.Read(buf, binary.BigEndian, &maskLen)
			mask = net.CIDRMask(int(maskLen), 128)
			rro := Rro{Type: soType, Addr: &net.IPNet{IP: ip, Mask: mask}}
			binary.Read(buf, binary.BigEndian, &flags)
			rro.LocalProtAvailable = 1&flags != 0
			rro.LocalProtInUse = 1<<1&flags != 0
			subObjects = append(subObjects, rro)
		case SUBOBJECT_LABEL:
			var label uint32
			buf.Next(2) // ignore flags/ctype
			binary.Read(buf, binary.BigEndian, &label)
			subObjects[counter-1].RecordedLabel = label
			continue
		default:
			glog.V(4).Infof("Rro.Parse: UnsupportedSubObject Type %d", soType)
			buf.Next(int(soLen))
			continue
		}
		counter++
	}
	o.ReportedRoutes = append(o.ReportedRoutes, subObjects...)
	return
}

func (o ReportedRouteObject) Serialize() []byte {
	// we should never really need to serialize an RRO
	return []byte{}
}

// The LSPA (LSP Attributes) object is optional and specifies various TE
// LSP attributes to be taken into account by the PCE during path
// computation.  The LSPA object can be carried within a PCReq message,
// or a PCRep message in case of unsuccessful path computation (in this
// case, the PCRep message also contains a NO-PATH object, and the LSPA
// object is used to indicate the set of constraints that could not be
// satisfied).
type LSPAObject struct {
	ExcludeAny, IncludeAny, IncludeAll uint32
	SetupPri, HoldPri                  uint8
	LocalProtectionDesired             bool
}

func (o *LSPAObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.BigEndian, &o.ExcludeAny)
	binary.Read(buf, binary.BigEndian, &o.IncludeAny)
	binary.Read(buf, binary.BigEndian, &o.IncludeAll)
	binary.Read(buf, binary.BigEndian, &o.SetupPri)
	binary.Read(buf, binary.BigEndian, &o.HoldPri)
	flags, _ := buf.ReadByte()
	o.LocalProtectionDesired = 1&flags != 0
	return
}

func (o LSPAObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, o.ExcludeAny)
	binary.Write(buf, binary.BigEndian, o.IncludeAny)
	binary.Write(buf, binary.BigEndian, o.IncludeAll)
	binary.Write(buf, binary.BigEndian, o.SetupPri)
	binary.Write(buf, binary.BigEndian, o.HoldPri)
	var l int
	if o.LocalProtectionDesired {
		l = 1
	}
	flags := uint8(l)
	binary.Write(buf, binary.BigEndian, flags)
	binary.Write(buf, binary.BigEndian, uint8(0))
	return buf.Bytes()
}

// The IRO (Include Route Object) is optional and can be used to specify
// that the computed path MUST traverse a set of specified network elements
type IncludeRouteObject struct {
	IncludeRoutes []Ero
}

func (o *IncludeRouteObject) Parse(data []byte) (err error) {
	// An Include route object is the same os an ERO
	o.IncludeRoutes = parseEroSubObjects(data)
	return
}

func (o IncludeRouteObject) Serialize() []byte {
	ero := ExplicitRouteObject{}
	copy(ero.ExplicitRoutes, o.IncludeRoutes)
	return ero.Serialize()
}

// The aim of the SVEC object carried within a PCReq message is to
// request the synchronization of M path computation requests.
type SvecObject struct {
	LinkDiverse, NodeDiverse, SRLGDiverse bool
	RequestIDs                            []uint32
}

func (o *SvecObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(3)
	flags, _ := buf.ReadByte()
	o.SRLGDiverse = 1<<2&flags != 0
	o.NodeDiverse = 1<<1&flags != 0
	o.LinkDiverse = 1&flags != 0
	for buf.Len() > 0 {
		var rid uint32
		binary.Read(buf, binary.BigEndian, &rid)
		o.RequestIDs = append(o.RequestIDs, rid)
	}
	return
}

func (o SvecObject) Serialize() []byte {
	return []byte{}
}

// The NOTIFICATION object is exclusively carried within a PCNtf message
// and used for event notifications
type NotificationObject struct {
	NotifType, NotifValue uint8
}

func (o *NotificationObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(2)
	binary.Read(buf, binary.BigEndian, &o.NotifType)
	binary.Read(buf, binary.BigEndian, &o.NotifValue)
	return
}

func (o NotificationObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, o.NotifType)
	binary.Write(buf, binary.BigEndian, o.NotifValue)
	return buf.Bytes()
}

// The PCEP-ERROR object is exclusively carried within a PCErr message
// to notify of a PCEP error.
type PcepErrorObject struct {
	ErrorType, ErrorValue uint8
}

func (o *PcepErrorObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(2)
	binary.Read(buf, binary.BigEndian, &o.ErrorType)
	binary.Read(buf, binary.BigEndian, &o.ErrorValue)
	return
}

func (o PcepErrorObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, o.ErrorType)
	binary.Write(buf, binary.BigEndian, o.ErrorValue)
	return buf.Bytes()
}

// There are situations where no TE LSP with a bandwidth of X could be
// found by a PCE although such a bandwidth requirement could be
// satisfied by a set of TE LSPs such that the sum of their bandwidths
// is equal to X.  Thus, it might be useful for a PCC to request a set
// of TE LSPs so that the sum of their bandwidth is equal to X Mbit/s,
// with potentially some constraints on the number of TE LSPs and the
// minimum bandwidth of each of these TE LSPs.  Such a request is made
// by inserting a LOAD-BALANCING object in a PCReq message sent to a
// PCE.
type LoadBalancingObject struct {
}

// The CLOSE object MUST be present in each Close message.
type CloseObject struct {
	CloseReason int
}

func (o *CloseObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(3)
	var reason uint8
	binary.Read(buf, binary.BigEndian, &reason)
	o.CloseReason = int(reason)
	return
}

func (o CloseObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint8(0))
	binary.Write(buf, binary.BigEndian, uint8(o.CloseReason))
	return buf.Bytes()
}

// The SRP (Stateful PCE Request Parameters) object MUST be carried
//    within PCUpd messages and MAY be carried within PCRpt and PCErr
//    messages.  The SRP object is used to correlate between update
//    requests sent by the PCE and the error reports and state reports sent
//    by the PCC.
type SRPObject struct {
	SrpId  uint32
	Remove bool
}

func (o *SRPObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	buf.Next(4) // ignore flags
	binary.Read(buf, binary.BigEndian, &o.SrpId)
	return
}

func (o SRPObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	var r int
	if o.Remove {
		r = 1
	}
	flags := uint32(r)
	binary.Write(buf, binary.BigEndian, flags)
	binary.Write(buf, binary.BigEndian, o.SrpId)
	return buf.Bytes()
}

// The LSP object contains a set of fields used to specify the target LSP, the
// operation to be performed on the LSP, and LSP Delegation.
type LSPObject struct {
	PLspID int
	Delegate,
	Sync,
	Remove,
	Admin,
	Create bool
	OperState        int
	Sender, Endpoint net.IP
	LspID, TunnelID  uint16
	ExtendedTunnelID uint32
	SymbolicPathName string
	LspErrorCode     int
}

func (o *LSPObject) Parse(data []byte) (err error) {
	buf := bytes.NewBuffer(data)
	var first uint32
	binary.Read(buf, binary.BigEndian, &first)
	o.PLspID = int(first >> 12)
	o.Delegate = 1&first != 0
	o.Sync = 1<<1&first != 0
	o.Remove = 1<<2&first != 0
	o.Admin = 1<<3&first != 0
	o.OperState = int(first >> 4 & 7)
	o.Create = 1<<7&first != 0
	allTlvLen := buf.Len()
	var tType, tLen uint16
	for buf.Len() > 0 {
		binary.Read(buf, binary.BigEndian, &tType)
		binary.Read(buf, binary.BigEndian, &tLen)
		value := buf.Next(int(tLen))
		// all lsp endpoints are assumed to be ipv4 only
		switch int(tType) {
		case TLV_TYPE_IPV4_LSP_IDENTIFIERS:
			var sum int
			for _, v := range value {
				sum += int(v)
			}
			if sum == 0 {
				// The special value of all zeros for this TLV is used
				// to refer to all paths pertaining to a particular PLSP-ID
				continue
			}
			tmp := bytes.NewBuffer(value)
			o.Sender = makeIP(tmp.Next(4))
			binary.Read(tmp, binary.BigEndian, &o.LspID)
			binary.Read(tmp, binary.BigEndian, &o.TunnelID)
			binary.Read(tmp, binary.BigEndian, &o.ExtendedTunnelID)
			o.Endpoint = makeIP(tmp.Next(4))
		case TLV_TYPE_SYMBOLIC_PATH_NAME:
			o.SymbolicPathName = string(value)
			// this tlv is 0-padded for 4-byte alignment
			padLen := (allTlvLen - 4 - int(tLen)) % 4
			buf.Next(padLen)
		case TLV_TYPE_LSP_ERROR_CODE:
			var errCode uint32
			tmp := bytes.NewBuffer(value)
			binary.Read(tmp, binary.BigEndian, &errCode)
			o.LspErrorCode = int(errCode)
		default:
			buf.Next(int(tLen))
		}
	}
	return
}

func (o LSPObject) Serialize() []byte {
	buf := &bytes.Buffer{}
	var d, s, r, a int
	if o.Delegate {
		d = 1
	}
	if o.Sync {
		s = 1
	}
	if o.Remove {
		r = 1
	}
	if o.Admin {
		a = 1
	}
	first := uint32(o.PLspID<<12 | o.OperState<<4 | a<<3 | r<<2 | s<<1 | d)
	binary.Write(buf, binary.BigEndian, &first)
	// write the LSP ID TLV , value set to all 0 to indicate all paths
	binary.Write(buf, binary.BigEndian, uint16(TLV_TYPE_IPV4_LSP_IDENTIFIERS))
	binary.Write(buf, binary.BigEndian, uint16(16))
	tmp := [16]byte{}
	buf.Write(tmp[:])
	// write the Symbolic-Path-Name TLV if required
	if o.SymbolicPathName != "" {
		binary.Write(buf, binary.BigEndian, uint16(TLV_TYPE_SYMBOLIC_PATH_NAME))
		nameBytes := []byte(o.SymbolicPathName)
		binary.Write(buf, binary.BigEndian, uint16(len(nameBytes)))
		buf.Write(nameBytes)
		// add padding
		padLen := 4 - len(nameBytes)%4
		padding := make([]byte, padLen)
		buf.Write(padding)
	}
	return buf.Bytes()
}
