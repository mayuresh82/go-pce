package pcep

import (
	"fmt"
	"github.com/golang/glog"
	"net"
	"strings"
	"sync"
)

type lspState int

const (
	LSP_DOWN       lspState = 0
	LSP_UP         lspState = 1
	LSP_ACTIVE     lspState = 2
	LSP_GOING_DOWN lspState = 3
	LSP_GOING_UP   lspState = 4
)

var stateToName map[lspState]string = map[lspState]string{
	LSP_DOWN:       "DOWN",
	LSP_UP:         "UP",
	LSP_ACTIVE:     "ACTIVE",
	LSP_GOING_DOWN: "GOING_DOWN",
	LSP_GOING_UP:   "GOING_UP",
}

// Every new lsp update request has a new srp id. see objects.go for more info.
var srpIdPointer int = 1

func getNewSrpId() int {
	srpId := srpIdPointer
	srpIdPointer = srpId + 1
	return srpId
}

type LspAttrs struct {
	Bandwidth,
	MaxMetric,
	PathMetric float32
	ExcludeAny        uint32
	IncludeRoutes     []Ero
	SetupPri, HoldPri int
	LocalProtDesired  bool
}

// LSP Represents a single LSP and all of its attributes
type Lsp struct {
	PLspID                             int
	Delegated, Created, DesiredAdminUp bool
	State                              lspState
	Src, Dst                           net.IP
	IntendedPath, ComputedPath         []Ero
	ReportedPath                       []Rro
	PathName                           string
	Attrs                              *LspAttrs
}

func NewLsp() *Lsp {
	return &Lsp{Attrs: &LspAttrs{}}
}

// String representation of an LSP
func (l *Lsp) String() string {
	s := fmt.Sprintf("Id: %d, Name: %s, State: %s, Src: %s, Dst: %s, BW: %d, Metric: %d",
		l.PLspID, l.PathName, stateToName[l.State], l.Src.String(), l.Dst.String(),
		int(l.Attrs.Bandwidth), int(l.Attrs.PathMetric))
	var ePath, rPath []string
	for _, ero := range l.IntendedPath {
		ePath = append(ePath, ero.String())
	}
	for _, rro := range l.ReportedPath {
		rPath = append(rPath, rro.String())
	}
	return fmt.Sprintf(
		"%s, Ero: %s, Rro: %s", s, strings.Join(ePath, ","), strings.Join(rPath, ","))
}

func (l *Lsp) SetDelegate(delegated bool) {
	l.Delegated = delegated
}

// Placeholder for getting an lsp path from an external pce controller
func (l *Lsp) ComputePath() error {
	return fmt.Errorf("PCE Unavailable")
}

// LSP Database per router, holds a map for easy lsp lookup
type lspDb struct {
	NumLsps, NumDelegated int
	// map of LspID -> Lsp
	Lsps map[int]*Lsp

	// mutex for concurrent r/w access
	sync.Mutex
}

func NewLspDb() *lspDb {
	return &lspDb{Lsps: make(map[int]*Lsp)}
}

func (db *lspDb) GetCount() (int, int) {
	db.Lock()
	defer db.Unlock()
	return db.NumLsps, db.NumDelegated
}

// Adds a single LSP to the db, accounting for updates and delegations
func (db *lspDb) Add(lsp *Lsp) {
	db.Lock()
	defer db.Unlock()
	// TODO Buffer lsps for the same ID until timeout before updating
	_, ok := db.Lsps[lsp.PLspID]
	if !ok {
		glog.V(4).Infof("Adding new LSP with ID: %d", lsp.PLspID)
		db.NumLsps++
		if lsp.Delegated {
			db.NumDelegated++
		}
	} else {
		glog.V(4).Infof("Updating LSP: %d", lsp.PLspID)
	}
	db.Lsps[lsp.PLspID] = lsp
}

// removes a single LSP from the db
func (db *lspDb) Remove(pLspId int) {
	db.Lock()
	defer db.Unlock()
	glog.V(4).Infof("Removing LSP: %d", pLspId)
	delete(db.Lsps, pLspId)
}

// LSP Database from all devices. This has a map of per-router lspdb
type GlobalLspDb struct {
	// map of pcclientName -> client LSP DB
	routerLspDb map[string]*lspDb

	// mutex for concurrent r/w access
	sync.Mutex
}

func NewGlobalLspDb() *GlobalLspDb {
	return &GlobalLspDb{
		routerLspDb: make(map[string]*lspDb),
	}
}

// Adds a single PCClient to the db
func (gdb *GlobalLspDb) AddPcc(pcc *PCC) {
	gdb.Lock()
	defer gdb.Unlock()
	gdb.routerLspDb[pcc.Name] = pcc.LspDB
}

// Removes a single PCClient from the db
func (gdb *GlobalLspDb) RemovePcc(pccName string) {
	gdb.Lock()
	defer gdb.Unlock()
	delete(gdb.routerLspDb, pccName)
}

// Gets the lsp db for a specific PCClient from the global db
func (gdb *GlobalLspDb) GetRouterLspDb(router string) (*lspDb, error) {
	gdb.Lock()
	defer gdb.Unlock()
	db, ok := gdb.routerLspDb[router]
	if ok {
		return db, nil
	} else {
		return db, fmt.Errorf("Router %s lspdb does not exist", router)
	}
}

// An update request is used to (re)signal or create/delete an LSP
type LspUpdateRequest struct {
	SrpId  int
	Lsp    *Lsp
	Delete bool
}

func NewLspUpdateRequest(lsp *Lsp, delete bool) *LspUpdateRequest {
	return &LspUpdateRequest{
		SrpId:  getNewSrpId(),
		Lsp:    lsp,
		Delete: delete,
	}
}

// A PceRequest is a request for a path computation
type PceRequest struct {
	Priority int
	ReOpt,
	Loose bool
	RequestID int
	Lsp       *Lsp
}

func NewPceRequest() *PceRequest {
	return &PceRequest{
		Lsp: &Lsp{
			Attrs: &LspAttrs{},
		},
	}
}

// A PceReply contains a computed path for a specific request
type PceReply struct {
	RequestID int
	Lsp       *Lsp
}

func (r *PceRequest) ComputePath() *PceReply {
	glog.V(4).Infof("Computing ero path for requestID: %d", r.RequestID)
	// compute and update lsp db
	r.Lsp.ComputePath()
	return &PceReply{RequestID: r.RequestID, Lsp: r.Lsp}
}
