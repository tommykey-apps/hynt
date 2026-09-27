// Package hynt は、ホストが繋がっているネットワークを VPN を含めて集める。
// 図のツールなど他のプログラムからは Collect を呼ぶ。CLI は cmd/hynt にある。
//
// 個別に欲しければ link / route / neigh / xfrm の各パッケージを直接呼んでもよい。
package hynt

import (
	"context"
	"errors"
	"os"

	"github.com/tommykey-apps/hynt/firewall"
	"github.com/tommykey-apps/hynt/link"
	"github.com/tommykey-apps/hynt/listen"
	"github.com/tommykey-apps/hynt/neigh"
	"github.com/tommykey-apps/hynt/route"
	"github.com/tommykey-apps/hynt/xfrm"
)

// Schema は JSON の形式の版。項目を削ったり意味を変えたりしたときだけ上げる。
// 項目を足すだけなら上げない (読む側は知らない項目を無視する)
const Schema = 1

type Report struct {
	Schema   int           `json:"schema"`
	Host     string        `json:"host"`
	Links    []link.Link   `json:"links"`
	Routes   []route.Route `json:"routes"`
	Rules    []route.Rule  `json:"rules"`
	Neighs   []neigh.Neigh `json:"neighs"`
	Policies []xfrm.Policy `json:"ipsec"`
	// IPsecDenied は ip xfrm policy が権限不足で読めなかったとき true。Policies は空
	IPsecDenied bool `json:"ipsec_denied"`
	// Listens は待ち受けているソケット。外から入ってこられる口
	Listens []listen.Socket `json:"listens"`
	// Firewall は nftables の input の規則。FirewallState が FirewallRead のときだけ中身がある
	Firewall      []firewall.Chain `json:"firewall"`
	FirewallState string           `json:"firewall_state"`
}

// FirewallState の値
const (
	FirewallRead    = "read"    // 読めた。規則が 0 件なら、塞いでいるものは無い
	FirewallDenied  = "denied"  // root でなく読めなかった
	FirewallMissing = "missing" // nft が入っていない
)

// Collect は ip / ss / nft コマンドと /sys/class/net を読んで Report を返す。root は要らない。
// root でなければ IPsec とファイアウォールが読めず、IPsecDenied が true、
// FirewallState が FirewallDenied になる (エラーにはしない)
func Collect(ctx context.Context) (Report, error) {
	r := Report{Schema: Schema}
	var err error
	r.Host, _ = os.Hostname()
	if r.Links, err = link.List(ctx); err != nil {
		return r, err
	}
	if r.Routes, err = route.List(ctx); err != nil {
		return r, err
	}
	if r.Rules, err = route.Rules(ctx); err != nil {
		return r, err
	}
	if r.Neighs, err = neigh.List(ctx); err != nil {
		return r, err
	}
	r.Policies, err = xfrm.List(ctx)
	if errors.Is(err, xfrm.ErrPermission) {
		r.IPsecDenied = true
		err = nil
	}
	if err != nil {
		return r, err
	}
	if r.Listens, err = listen.List(ctx); err != nil {
		return r, err
	}
	r.Firewall, err = firewall.List(ctx)
	switch {
	case errors.Is(err, firewall.ErrPermission):
		r.FirewallState = FirewallDenied
	case errors.Is(err, firewall.ErrNotInstalled):
		r.FirewallState = FirewallMissing
	case err != nil:
		return r, err
	default:
		r.FirewallState = FirewallRead
	}
	return r, nil
}
