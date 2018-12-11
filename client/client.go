package main

import (
	"context"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"log"
	"os"
	"pce/pcep"
	"text/tabwriter"
)

var (
	serverAddr  = flag.String("addr", "localhost:14841", "Addr for grpc server")
	listRouters = flag.Bool("listRouters", false, "List all active PCCs")
	listLsps    = flag.Bool("listLsps", false, "List all active LSPs from this router")
	router      = flag.String("router", "", "Router name to list LSPs from")
	lspName     = flag.String("lspName", "", "List specific LSP info")
)

func main() {
	flag.Parse()
	conn, err := grpc.Dial(*serverAddr, grpc.WithInsecure())
	if err != nil {
		log.Fatalf(err.Error())
	}
	defer conn.Close()
	client := pcep.NewPceServiceClient(conn)
	ctx := context.Background()
	if *listRouters {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "Name\tState\tStateful  \tSupCreate   \tSID")
		fmt.Fprintln(w, "-----\t------\t--------\t---------\t-------")
		routers, err := client.GetPccRouters(ctx, &pcep.Empty{})
		if err != nil {
			log.Fatalf(err.Error())
		}
		for _, router := range routers.Routers {
			fmt.Fprintf(w, "%s\t%s\t%v\t%v\t%d\n", router.Name, router.State.String(), router.IsStateful, router.SupportsCreate, router.SessionID)
		}
		w.Flush()
	}
}
