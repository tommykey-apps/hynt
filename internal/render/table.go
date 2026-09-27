// Package render は CLI の出力 (表 / JSON) を書く。ライブラリ利用者には関係しない
package render

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/link"
	"github.com/tommykey-apps/hynt/neigh"
	"github.com/tommykey-apps/hynt/route"
)

// Table は 1 つの表に全部を収める。1 インタフェース 1 グループで、アドレスや経路が複数あれば
// 2 行目以降は IF / KIND / STATE / NEIGH を空けて続ける。rule は表に出さない (--json にはある)。
// 表を分けると一覧の意味が薄れる
func Table(out io.Writer, r hynt.Report) error {
	counts := neigh.CountByDev(r.Neighs)
	byDev := map[string][]route.Route{}
	for _, rt := range r.Routes {
		byDev[rt.Dev] = append(byDev[rt.Dev], rt)
	}

	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IF\tKIND\tSTATE\tNEIGH\tADDR\tDST\tVIA\tTABLE")
	for _, l := range r.Links {
		rts := byDev[l.Name]
		for i := 0; i < max(len(l.Addrs), len(rts), 1); i++ {
			head := "\t\t\t"
			if i == 0 {
				head = fmt.Sprintf("%s\t%s\t%s\t%d", l.Name, kindLabel(l), l.State, counts[l.Name])
			}
			// 1 行目だけ空欄を - にする。2 行目以降は空白のままの方が続きだと分かる
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
	for _, p := range r.Policies {
		fmt.Fprintf(w, "(ipsec)\tipsec %s\t-\t-\t%s\t%s\t%s\t-\n", p.Mode, p.Src, p.Dst, p.Gateway)
	}
	// Why not: 日本語を表に入れない。tabwriter は全角幅を数えないので列がずれる
	if r.IPsecDenied {
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
