// hynt は、ホストが繋がっているネットワークを VPN を含めて 1 つの表に出す
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tommykey-apps/hynt/link"
	"github.com/tommykey-apps/hynt/neigh"
	"github.com/tommykey-apps/hynt/route"
	"github.com/tommykey-apps/hynt/xfrm"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "hynt:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()
	links, err := link.List(ctx)
	if err != nil {
		return err
	}
	routes, err := route.List(ctx)
	if err != nil {
		return err
	}
	neighs, err := neigh.List(ctx)
	if err != nil {
		return err
	}
	// IPsec は root でないと読めない。読めなくても表は出す
	policies, xfrmErr := xfrm.List(ctx)
	if xfrmErr != nil && !errors.Is(xfrmErr, xfrm.ErrPermission) {
		return xfrmErr
	}

	counts := neigh.CountByDev(neighs)
	byDev := map[string][]route.Route{}
	for _, rt := range routes {
		byDev[rt.Dev] = append(byDev[rt.Dev], rt)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IF\tKIND\tSTATE\tNEIGH\tADDR\tDST\tVIA\tTABLE")
	for _, l := range links {
		rts := byDev[l.Name]
		for i := 0; i < max(len(l.Addrs), len(rts), 1); i++ {
			head := "\t\t\t"
			if i == 0 {
				head = fmt.Sprintf("%s\t%s\t%s\t%d", l.Name, kindLabel(l), l.State, counts[l.Name])
			}
			addr, dst, via, table := "", "", "", ""
			if i == 0 {
				addr, dst, via, table = "-", "-", "-", "-"
			}
			if i < len(l.Addrs) {
				addr = l.Addrs[i]
			}
			if i < len(rts) {
				dst, via, table = rts[i].Dst, dash(rts[i].Gateway), rts[i].Table
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", head, addr, dst, via, table)
		}
	}
	// policy-based IPsec はインタフェースを持たないので、仮の行名で並べる
	for _, p := range policies {
		fmt.Fprintf(w, "(ipsec)\tipsec %s\t-\t-\t%s\t%s\t%s\t-\n", p.Mode, p.Src, p.Dst, p.Gateway)
	}
	// Why not: 日本語を表に入れない。tabwriter は全角幅を数えないので列がずれる
	if xfrmErr != nil {
		fmt.Fprintln(w, "(ipsec)\tipsec\tDENIED\t-\t-\t-\t-\t-")
	}
	return w.Flush()
}

func kindLabel(l link.Link) string {
	if l.Impl == "" || l.Impl == string(l.Kind) {
		return string(l.Kind)
	}
	return string(l.Kind) + " " + l.Impl
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
