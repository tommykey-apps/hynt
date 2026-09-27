package route

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

type Route struct {
	Dst     string `json:"dst"`     // "default" か CIDR
	Gateway string `json:"gateway"` // 直結なら空
	Dev     string `json:"dev"`
	Table   string `json:"table"` // "main" / "52" など
	Metric  int    `json:"metric"`
}

type Rule struct {
	Priority int    `json:"priority"`
	Selector string `json:"selector"` // "from all" / "from all fwmark 0x80000/0xff0000" / "not from all fwmark 0xca6c" など
	Table    string `json:"table"`    // action が unreachable などのときは空
	Action   string `json:"action"`
	// SuppressPrefixlen は suppress_prefixlength。この長さ以下の経路を無視する。
	// wg-quick は 0 を付けて main の default を無視させる。付いていなければ nil
	SuppressPrefixlen *int `json:"suppress_prefixlength,omitempty"`
}

// ip -j route show table all の1件。必要な項目だけ持つ
type ipRoute struct {
	Type    string `json:"type"` // 空 = unicast
	Dst     string `json:"dst"`
	Gateway string `json:"gateway"`
	Dev     string `json:"dev"`
	Table   string `json:"table"` // 空 = main
	Metric  int    `json:"metric"`
}

type ipRule struct {
	Priority int    `json:"priority"`
	Src      string `json:"src"`
	Dst      string `json:"dst"`
	Fwmark   string `json:"fwmark"`
	Fwmask   string `json:"fwmask"`
	Table    string `json:"table"`
	Action   string `json:"action"`
	// "not" は値が null で、有無だけが意味を持つ。*T だと null で nil になり区別できないので RawMessage で受ける
	Not               json.RawMessage `json:"not"`
	SuppressPrefixlen *int            `json:"suppress_prefixlen"`
}

func List(ctx context.Context) ([]Route, error) {
	// Why not: table を省くと main しか出ず、Tailscale (52) や wg-quick (51820) の経路が消える
	out, err := exec.CommandContext(ctx, "ip", "-j", "route", "show", "table", "all").Output()
	if err != nil {
		return nil, fmt.Errorf("ip route: %w", err)
	}
	return parseRoutes(out)
}

func Rules(ctx context.Context) ([]Rule, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "rule", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip rule: %w", err)
	}
	return parseRules(out)
}

func parseRoutes(raw []byte) ([]Route, error) {
	var items []ipRoute
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&items); err != nil {
		return nil, fmt.Errorf("ip route の JSON を読めない: %w", err)
	}
	var routes []Route
	for _, it := range items {
		switch {
		case it.Type != "" && it.Type != "unicast": // local / broadcast / multicast
			continue
		case it.Table == "local":
			continue
		case strings.HasPrefix(it.Dst, "fe80:"): // link-local は全インタフェースにあり情報にならない
			continue
		}
		table := it.Table
		if table == "" {
			table = "main"
		}
		routes = append(routes, Route{Dst: it.Dst, Gateway: it.Gateway, Dev: it.Dev, Table: table, Metric: it.Metric})
	}
	slices.SortFunc(routes, func(a, b Route) int {
		if c := strings.Compare(a.Dev, b.Dev); c != 0 {
			return c
		}
		if c := strings.Compare(a.Table, b.Table); c != 0 {
			return c
		}
		// default を先頭に
		if (a.Dst == "default") != (b.Dst == "default") {
			if a.Dst == "default" {
				return -1
			}
			return 1
		}
		if c := strings.Compare(a.Dst, b.Dst); c != 0 {
			return c
		}
		// IPv4 と IPv6 の default が同じ dev に並ぶので、gateway で順を固定する
		return strings.Compare(a.Gateway, b.Gateway)
	})
	return routes, nil
}

func parseRules(raw []byte) ([]Rule, error) {
	var items []ipRule
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&items); err != nil {
		return nil, fmt.Errorf("ip rule の JSON を読めない: %w", err)
	}
	rules := make([]Rule, 0, len(items))
	for _, it := range items {
		sel := "from " + it.Src
		if len(it.Not) > 0 {
			sel = "not " + sel
		}
		if it.Dst != "" {
			sel += " to " + it.Dst
		}
		if it.Fwmark != "" {
			sel += " fwmark " + it.Fwmark
			if it.Fwmask != "" {
				sel += "/" + it.Fwmask
			}
		}
		rules = append(rules, Rule{Priority: it.Priority, Selector: sel, Table: it.Table, Action: it.Action, SuppressPrefixlen: it.SuppressPrefixlen})
	}
	slices.SortFunc(rules, func(a, b Rule) int { return a.Priority - b.Priority })
	return rules, nil
}
