package main

import (
	"context"
	"fmt"
	"github.com/mayuresh82/go-pce/pcep"
	"net"
	"strings"

	"github.com/golang/glog"
)

type PceServer struct{}

// GetPccRouters returns a list of active PC Client routers
func (s *PceServer) GetPccRouters(ctx context.Context, none *pcep.Empty) (*pcep.PccRouters, error) {
	routers := &pcep.PccRouters{Routers: []*pcep.PccRouter{}}
	for router, pcc := range sessions {
		state := pcc.GetState()
		var ifState pcep.PccState = pcep.PccState_IDLE
		if state == pcep.UP {
			ifState = pcep.PccState_UP
		}
		isStateFul, supportsCreate := pcc.GetProperties()
		routers.Routers = append(routers.Routers, &pcep.PccRouter{
			Name:           router,
			State:          ifState,
			IsStateful:     isStateFul,
			SupportsCreate: supportsCreate,
			SessionID:      int32(pcc.GetSessionID()),
		})
	}
	return routers, nil
}

// GetLspDump returns a complete lsp dump from a router-ip
func (s *PceServer) GetLspDump(ctx context.Context, request *pcep.LspDumpRequest) (*pcep.LspDumpResponse, error) {
	events := &pcep.LspDumpResponse{Lsps: []*pcep.LspEvent{}}
	lspdb, err := globalLspDb.GetRouterLspDb(request.RouterIP)
	if err != nil {
		return events, fmt.Errorf("%s is not a valid routerIP", request.RouterIP)
	}
	lspdb.Lock()
	defer lspdb.Unlock()
	for _, lsp := range lspdb.Lsps {
		pbLsp := getIfLsp(lsp)
		switch lsp.State {
		case pcep.LSP_UP, pcep.LSP_ACTIVE:
			pbLsp.Active = true
		default:
			pbLsp.Active = false
		}
		events.Lsps = append(events.Lsps, &pcep.LspEvent{
			Type:     pcep.LspEventType_LSP_UP,
			RouterIP: request.RouterIP,
			Lsp:      pbLsp,
		})
	}
	return events, nil
}

// getIfLsp returns a pb-Lsp from a given pcep-lsp
func getIfLsp(lsp *pcep.Lsp) *pcep.PbLsp {
	pbLsp := &pcep.PbLsp{
		LspID:         int32(lsp.PLspID),
		Name:          strings.Split(lsp.PathName, "/")[0],
		SourceIP:      lsp.Src.String(),
		DestinationIP: lsp.Dst.String(),
	}
	rro := []*pcep.LspRro{}
	for _, hop := range lsp.ReportedPath {
		rro = append(rro, &pcep.LspRro{
			HopIP:                hop.Addr.String(),
			RecordedLabel:        int32(hop.RecordedLabel),
			LocalProtectionInUse: hop.LocalProtInUse,
		})
	}
	ero := []*pcep.LspEro{}
	for _, hop := range lsp.IntendedPath {
		ero = append(ero, &pcep.LspEro{
			Loose: hop.Loose,
			HopIP: hop.Addr.String(),
		})
	}
	pbLsp.Attrs = &pcep.LspAttributes{
		SetupPriority:     int32(lsp.Attrs.SetupPri),
		HoldPriority:      int32(lsp.Attrs.HoldPri),
		ReservedBandwidth: int64(lsp.Attrs.Bandwidth),
		MaxAvgBandwidth:   0,
		PathMetric:        int32(lsp.Attrs.PathMetric),
		ReportedPath:      rro,
		ExplicitPath:      ero,
		ExcludeAny:        getAdminGroups(lsp.Attrs.ExcludeAny),
	}
	return pbLsp
}

// getAdminGroups returns a slice of admin groups from a bit-mask
func getAdminGroups(excludeAny uint32) []int32 {
	var adminGroups []int32
	for i := 0; i < 31; i++ {
		if 1<<uint(i)&excludeAny != 0 {
			adminGroups = append(adminGroups, int32(i))
		}
	}
	return adminGroups
}

// getExcludeAny returns a slice of exclude-groups from a bit-mask
func getExcludeAny(adminGroups []int32) uint32 {
	var excludeAny uint32
	for _, group := range adminGroups {
		excludeAny |= (1 << uint(group))
	}
	return excludeAny
}

// getPcepEro returns a pcep-ero from a given pb-ero
func getPcepEro(ifPath []*pcep.LspEro) ([]pcep.Ero, error) {
	eroPath := []pcep.Ero{}
	for _, hop := range ifPath {
		_, ipaddr, err := net.ParseCIDR(hop.HopIP)
		if err != nil {
			glog.Infof(err.Error())
			return eroPath, err
		}
		ero := pcep.Ero{
			Loose: hop.Loose,
			Type:  pcep.SUBOBJECT_IPV4,
			Addr:  ipaddr}
		eroPath = append(eroPath, ero)
	}
	return eroPath, nil
}

// getPcepLsp returns a pce-lsp from a thrift-lsp
func getPcepLsp(pbLsp *pcep.PbLsp) (*pcep.Lsp, error) {
	lsp := pcep.NewLsp()
	lsp.Src = net.ParseIP(pbLsp.SourceIP)
	lsp.Dst = net.ParseIP(pbLsp.DestinationIP)
	ero, err := getPcepEro(pbLsp.Attrs.ExplicitPath)
	if err != nil {
		return nil, err
	}
	lsp.PathName = pbLsp.Name
	lsp.ComputedPath = ero
	lsp.Attrs.Bandwidth = float32(pbLsp.Attrs.ReservedBandwidth / 8)
	lsp.Attrs.PathMetric = float32(pbLsp.Attrs.PathMetric)
	lsp.Attrs.SetupPri = int(pbLsp.Attrs.SetupPriority)
	lsp.Attrs.HoldPri = int(pbLsp.Attrs.HoldPriority)
	lsp.Attrs.ExcludeAny = getExcludeAny(pbLsp.Attrs.ExcludeAny)
	return lsp, nil
}

// UpdateLsps updates lsp attributes for a given router
func (s *PceServer) UpdateLsps(ctx context.Context, request *pcep.UpdateLspRequest) (*pcep.LspResponse, error) {
	lspdb, err := globalLspDb.GetRouterLspDb(request.Router)
	if err != nil {
		return &pcep.LspResponse{}, err
	}
	lspdb.Lock()
	defer lspdb.Unlock()
	requests := []*pcep.LspUpdateRequest{}
	for lspID, attrs := range request.LspChanges {
		existingLsp, ok := lspdb.Lsps[int(lspID)]
		if !ok {
			glog.Infof("Cant find LSP ID: %d", lspID)
			continue
		}
		if !existingLsp.Delegated {
			glog.Errorf("Lsp ID %d is non-delegated, cannot re-signal", lspID)
			continue
		}
		eroPath, err := getPcepEro(attrs.ExplicitPath)
		if err != nil {
			return &pcep.LspResponse{}, err
		}
		// one of the below attributes could be changed.Caller needs to include
		// both changed and unchanged(original) values
		existingLsp.ComputedPath = eroPath
		existingLsp.Attrs.Bandwidth = float32(attrs.ReservedBandwidth / 8)
		existingLsp.Attrs.SetupPri = int(attrs.SetupPriority)
		existingLsp.Attrs.HoldPri = int(attrs.HoldPriority)
		existingLsp.Attrs.ExcludeAny = getExcludeAny(attrs.ExcludeAny)

		glog.V(4).Infof("Sending update request for LSP: %d", lspID)
		requests = append(requests, pcep.NewLspUpdateRequest(existingLsp, false))
	}
	if len(requests) > 0 {
		pcc, ok := sessions[request.Router]
		if ok && pcc.GetState() == pcep.UP {
			glog.Infof("Sending update request for %d Lsps to %s", len(requests), request.Router)
			pcc.AsyncUpdates <- requests
		}
	}
	return &pcep.LspResponse{Success: true}, nil
}

// CreateLsps creates brand new LSPs on a given router
func (s *PceServer) CreateLsps(ctx context.Context, request *pcep.CreateLspRequest) (*pcep.LspResponse, error) {
	requests := []*pcep.LspUpdateRequest{}
	for _, pbLsp := range request.LspsToCreate {
		pcepLsp, err := getPcepLsp(pbLsp)
		if err != nil {
			continue
		}
		requests = append(requests, pcep.NewLspUpdateRequest(pcepLsp, false))
	}
	// we dont update our LSPDB here, that is updated upon receipt of a report
	// from the device indicating success
	if len(requests) > 0 {
		pcc, ok := sessions[request.Router]
		if ok && pcc.GetState() == pcep.UP {
			glog.Infof("Sending create request for %d Lsps to %s", len(requests), request.Router)
			pcc.AsyncInit <- requests
		}
	}
	return &pcep.LspResponse{Success: true}, nil
}

// DeleteLsps deletes previously created pce-initiated lsps on a given router
func (s *PceServer) DeleteLsps(ctx context.Context, request *pcep.DeleteLspRequest) (*pcep.LspResponse, error) {
	lspdb, err := globalLspDb.GetRouterLspDb(request.Router)
	if err != nil {
		return &pcep.LspResponse{}, err
	}
	lspdb.Lock()
	defer lspdb.Unlock()
	requests := []*pcep.LspUpdateRequest{}
	for _, lspID := range request.LspIDs {
		existingLsp, ok := lspdb.Lsps[int(lspID)]
		if !ok {
			glog.Infof("Cant find LSP ID: %d", lspID)
			continue
		}
		if !existingLsp.Created {
			glog.Errorf("Lsp ID %d is non-created, cannot delete", lspID)
			continue
		}
		requests = append(requests, pcep.NewLspUpdateRequest(existingLsp, true))
		glog.V(4).Infof("Sending delete request for LSP: %d", lspID)
	}
	if len(requests) > 0 {
		pcc, ok := sessions[request.Router]
		if ok && pcc.GetState() == pcep.UP {
			glog.Infof("Sending delete request for %d Lsps to %s", len(requests), request.Router)
			pcc.AsyncInit <- requests
		}
	}
	return &pcep.LspResponse{Success: true}, nil
}
