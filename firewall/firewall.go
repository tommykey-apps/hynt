// Package firewall は nftables の input の規則を読む。
// 外から入ってくる通信を通すか塞ぐかを判定できるよう、規則を
// 「受信口・プロトコル・宛先ポート・接続の状態 → 結果」の形に単純化する。
// 単純化できない条件 (送信元アドレスなど) は Unknown に文字列で残し、捨てない
package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"slices"
	"strings"
)

// ErrPermission は CAP_NET_ADMIN が無くて読めなかったとき
var ErrPermission = errors.New("nft list ruleset は root 権限が要る")

// ErrNotInstalled は nft コマンドが無いとき
var ErrNotInstalled = errors.New("nft が無い")

type Chain struct {
	Family string `json:"family"` // inet / ip / ip6
	Table  string `json:"table"`
	Name   string `json:"name"`
	Hook   string `json:"hook"`   // input。jump 先の通常のチェーンは空
	Prio   int    `json:"prio"`   // 小さいほど先に通る
	Policy string `json:"policy"` // accept / drop。通常のチェーンは空
	Rules  []Rule `json:"rules"`
}

type Rule struct {
	Iifnames []string    `json:"iifnames"`  // 受信口の名前。空ならすべて
	Protos   []string    `json:"protos"`    // tcp / udp / icmp など。空ならすべて
	Dports   []PortRange `json:"dports"`    // 宛先ポート。空ならすべて
	CtStates []string    `json:"ct_states"` // new / established / related / invalid。空ならすべて
	// Unknown は単純化できなかった条件。1 つでもあれば、この規則に当たるかは決まらない
	Unknown []string `json:"unknown"`
	// Verdict は accept / drop / reject / jump / goto / return。
	// 結果を持たない規則 (counter だけなど) は空、読めない結果 (vmap など) は unknown
	Verdict string `json:"verdict"`
	Target  string `json:"target"` // jump / goto の先
}

type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

func List(ctx context.Context) ([]Chain, error) {
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "ruleset")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if errors.Is(err, exec.ErrNotFound) {
		return nil, ErrNotInstalled
	}
	if strings.Contains(stderr.String(), "Operation not permitted") {
		return nil, ErrPermission
	}
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset: %w", err)
	}
	return parse(out)
}

// nft -j の 1 件は {"table":…} {"chain":…} {"set":…} {"rule":…} のどれか 1 つを持つ
type nftObject struct {
	Chain *struct {
		Family, Table, Name, Hook, Type, Policy string
		Prio                                    int
	} `json:"chain"`
	Set *struct {
		Family, Table, Name string
		Elem                []json.RawMessage
	} `json:"set"`
	Rule *struct {
		Family, Table, Chain string
		Expr                 []map[string]json.RawMessage
	} `json:"rule"`
}

func parse(raw []byte) ([]Chain, error) {
	var doc struct {
		Nftables []nftObject `json:"nftables"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("nft の JSON を読めない: %w", err)
	}

	// input のフックを持つ表だけを対象にする。jump 先はその表の中にある
	type key struct{ family, table, name string }
	inputTables := map[[2]string]bool{}
	for _, o := range doc.Nftables {
		if c := o.Chain; c != nil && c.Hook == "input" && c.Type == "filter" && ipFamily(c.Family) {
			inputTables[[2]string{c.Family, c.Table}] = true
		}
	}
	sets := map[key][]json.RawMessage{}
	var chains []Chain
	index := map[key]int{}
	for _, o := range doc.Nftables {
		switch {
		case o.Set != nil:
			sets[key{o.Set.Family, o.Set.Table, o.Set.Name}] = o.Set.Elem
		case o.Chain != nil:
			c := o.Chain
			if !inputTables[[2]string{c.Family, c.Table}] {
				continue
			}
			// 同じ表の中の output や forward は入ってくる通信に関わらない
			if c.Hook != "" && (c.Hook != "input" || c.Type != "filter") {
				continue
			}
			index[key{c.Family, c.Table, c.Name}] = len(chains)
			ch := Chain{Family: c.Family, Table: c.Table, Name: c.Name, Hook: c.Hook, Policy: c.Policy}
			if c.Hook != "" {
				ch.Prio = c.Prio
				if ch.Policy == "" {
					ch.Policy = "accept"
				}
			}
			chains = append(chains, ch)
		}
	}
	// Why not: rule を chain と同じ周回で読まない。nft は set を rule より後に出すことがあり、@name を引けない
	for _, o := range doc.Nftables {
		r := o.Rule
		if r == nil {
			continue
		}
		i, ok := index[key{r.Family, r.Table, r.Chain}]
		if !ok {
			continue
		}
		lookup := func(name string) []json.RawMessage { return sets[key{r.Family, r.Table, name}] }
		chains[i].Rules = append(chains[i].Rules, parseRule(r.Expr, lookup))
	}
	slices.SortStableFunc(chains, func(a, b Chain) int {
		// 基本のチェーンを優先度の順に前へ、jump 先は後ろへ
		if (a.Hook == "") != (b.Hook == "") {
			if a.Hook == "" {
				return 1
			}
			return -1
		}
		return a.Prio - b.Prio
	})
	return chains, nil
}

func ipFamily(f string) bool { return f == "inet" || f == "ip" || f == "ip6" }

func parseRule(exprs []map[string]json.RawMessage, lookup func(string) []json.RawMessage) Rule {
	var r Rule
	for _, e := range exprs {
		for kind, body := range e {
			switch kind {
			case "match":
				parseMatch(&r, body, lookup)
			case "accept", "drop", "reject", "return":
				r.Verdict = kind
			case "jump", "goto":
				var t struct{ Target string }
				_ = json.Unmarshal(body, &t)
				r.Verdict, r.Target = kind, t.Target
			case "counter", "log", "limit", "comment", "quota":
				// 結果に関わらない。limit は超えた分を次の規則へ流すが、ここでは当たる扱いにする
			default:
				// vmap、xt (iptables-nft)、mangle などは読まない
				r.Unknown = append(r.Unknown, kind)
				if kind == "vmap" || kind == "xt" {
					r.Verdict = "unknown"
				}
			}
		}
	}
	return r
}

func parseMatch(r *Rule, body json.RawMessage, lookup func(string) []json.RawMessage) {
	var m struct {
		Op    string
		Left  map[string]json.RawMessage
		Right json.RawMessage
	}
	if err := json.Unmarshal(body, &m); err != nil {
		r.Unknown = append(r.Unknown, string(body))
		return
	}
	unknown := func() { r.Unknown = append(r.Unknown, describe(m.Left, m.Op, m.Right)) }
	// != や範囲外の指定は「それ以外すべて」で、一覧に直せない
	if m.Op != "==" && m.Op != "in" {
		unknown()
		return
	}
	values := func() []json.RawMessage { return flatten(m.Right, lookup) }

	if meta, ok := m.Left["meta"]; ok {
		var k struct{ Key string }
		_ = json.Unmarshal(meta, &k)
		switch k.Key {
		case "iifname", "iif":
			r.Iifnames = append(r.Iifnames, stringsOf(values())...)
		case "l4proto":
			r.Protos = append(r.Protos, stringsOf(values())...)
		case "pkttype":
			// 外から自分へ繋ぎに来る通信は host (自分宛て) なので、host だけなら条件にならない
			if v := stringsOf(values()); len(v) != 1 || v[0] != "host" {
				unknown()
			}
		default:
			unknown()
		}
		return
	}
	if ct, ok := m.Left["ct"]; ok {
		var k struct{ Key string }
		_ = json.Unmarshal(ct, &k)
		if k.Key != "state" {
			unknown()
			return
		}
		r.CtStates = append(r.CtStates, stringsOf(values())...)
		return
	}
	if p, ok := m.Left["payload"]; ok {
		var f struct{ Protocol, Field string }
		_ = json.Unmarshal(p, &f)
		switch {
		case f.Field == "dport" && (f.Protocol == "tcp" || f.Protocol == "udp" || f.Protocol == "th"):
			if f.Protocol != "th" {
				r.Protos = append(r.Protos, f.Protocol)
			}
			ports, ok := portsOf(values())
			if !ok {
				unknown()
				return
			}
			r.Dports = append(r.Dports, ports...)
		case (f.Protocol == "ip" && f.Field == "protocol") || (f.Protocol == "ip6" && f.Field == "nexthdr"):
			r.Protos = append(r.Protos, stringsOf(values())...)
		default:
			unknown()
		}
		return
	}
	unknown()
}

// right は 値 / {"set":[…]} / "@名前" / {"range":[a,b]} のどれか。一覧に開く
func flatten(right json.RawMessage, lookup func(string) []json.RawMessage) []json.RawMessage {
	var name string
	if json.Unmarshal(right, &name) == nil && strings.HasPrefix(name, "@") {
		return lookup(name[1:])
	}
	var set struct{ Set []json.RawMessage }
	if json.Unmarshal(right, &set) == nil && set.Set != nil {
		return set.Set
	}
	return []json.RawMessage{right}
}

func stringsOf(vs []json.RawMessage) []string {
	var out []string
	for _, v := range vs {
		var s string
		if json.Unmarshal(v, &s) == nil {
			out = append(out, s)
			continue
		}
		out = append(out, string(v))
	}
	return out
}

// ポートは数値、{"range":[a,b]}、サービス名 ("ssh") のどれかで来る
func portsOf(vs []json.RawMessage) ([]PortRange, bool) {
	var out []PortRange
	for _, v := range vs {
		var n int
		if json.Unmarshal(v, &n) == nil {
			out = append(out, PortRange{n, n})
			continue
		}
		var rg struct{ Range [2]json.RawMessage }
		if json.Unmarshal(v, &rg) == nil && rg.Range[0] != nil {
			from, ok1 := portOf(rg.Range[0])
			to, ok2 := portOf(rg.Range[1])
			if !ok1 || !ok2 {
				return nil, false
			}
			out = append(out, PortRange{from, to})
			continue
		}
		p, ok := portOf(v)
		if !ok {
			return nil, false
		}
		out = append(out, PortRange{p, p})
	}
	return out, len(out) > 0
}

func portOf(v json.RawMessage) (int, bool) {
	var n int
	if json.Unmarshal(v, &n) == nil {
		return n, true
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return 0, false
	}
	p, err := net.LookupPort("tcp", s)
	return p, err == nil
}

// 読めなかった条件を人が読める形で残す。例: "ip saddr == {"prefix":{"addr":"192.0.2.0","len":24}}"
func describe(left map[string]json.RawMessage, op string, right json.RawMessage) string {
	var parts []string
	for kind, body := range left {
		var f struct{ Protocol, Field, Key string }
		_ = json.Unmarshal(body, &f)
		switch {
		case f.Protocol != "":
			parts = append(parts, f.Protocol+" "+f.Field)
		case f.Key != "":
			parts = append(parts, kind+" "+f.Key)
		default:
			parts = append(parts, kind)
		}
	}
	var compact bytes.Buffer
	if json.Compact(&compact, right) != nil {
		compact.Write(right)
	}
	return strings.Join(parts, " ") + " " + op + " " + compact.String()
}
