package render

import (
	"encoding/json"
	"io"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/link"
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
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
