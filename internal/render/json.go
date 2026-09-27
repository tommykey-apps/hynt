package render

import (
	"encoding/json"
	"io"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/firewall"
	"github.com/tommykey-apps/hynt/link"
	"github.com/tommykey-apps/hynt/listen"
	"github.com/tommykey-apps/hynt/neigh"
	"github.com/tommykey-apps/hynt/route"
	"github.com/tommykey-apps/hynt/xfrm"
)

func JSON(out io.Writer, r hynt.Report) error {
	// nil スライスは null になる。機械向けには [] の方が扱いやすい
	// Links は要素ごとに Addrs を書き換えるので複製する。呼び出し側の Report を変えない
	r.Links = append([]link.Link{}, r.Links...)
	for i := range r.Links {
		if r.Links[i].Addrs == nil {
			r.Links[i].Addrs = []string{}
		}
	}
	if r.Routes == nil {
		r.Routes = []route.Route{}
	}
	if r.Rules == nil {
		r.Rules = []route.Rule{}
	}
	if r.Neighs == nil {
		r.Neighs = []neigh.Neigh{}
	}
	if r.Policies == nil {
		r.Policies = []xfrm.Policy{}
	}
	if r.Listens == nil {
		r.Listens = []listen.Socket{}
	}
	// 規則の中の一覧も null にしない。Chains も Rules も複製してから書き換える
	chains := make([]firewall.Chain, len(r.Firewall))
	for i, c := range r.Firewall {
		rules := make([]firewall.Rule, len(c.Rules))
		for j, ru := range c.Rules {
			ru.Iifnames = orEmpty(ru.Iifnames)
			ru.Protos = orEmpty(ru.Protos)
			ru.CtStates = orEmpty(ru.CtStates)
			ru.Unknown = orEmpty(ru.Unknown)
			if ru.Dports == nil {
				ru.Dports = []firewall.PortRange{}
			}
			rules[j] = ru
		}
		c.Rules = rules
		chains[i] = c
	}
	r.Firewall = chains
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
