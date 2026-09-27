package neigh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// Neigh は ip neigh の1件。同じ LAN 上で最近通信した相手
type Neigh struct {
	Dst    string `json:"dst"` // IP
	Lladdr string `json:"mac"` // MAC
	Dev    string `json:"dev"`
	State  string `json:"state"` // REACHABLE / STALE / DELAY / PROBE / PERMANENT
}

type ipNeigh struct {
	Dst    string   `json:"dst"`
	Dev    string   `json:"dev"`
	Lladdr string   `json:"lladdr"`
	State  []string `json:"state"`
}

func List(ctx context.Context) ([]Neigh, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "neigh", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip neigh: %w", err)
	}
	return parse(out)
}

func parse(raw []byte) ([]Neigh, error) {
	var items []ipNeigh
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&items); err != nil {
		return nil, fmt.Errorf("ip neigh の JSON を読めない: %w", err)
	}
	var ns []Neigh
	for _, it := range items {
		// Why not: FAILED / INCOMPLETE は MAC が取れていない。相手がいる証拠にならないので捨てる
		if it.Lladdr == "" {
			continue
		}
		// link-local は同じ MAC が別の IP で重複して出るだけなので捨てる
		if strings.HasPrefix(it.Dst, "fe80:") {
			continue
		}
		state := ""
		if len(it.State) > 0 {
			state = it.State[0]
		}
		ns = append(ns, Neigh{Dst: it.Dst, Lladdr: it.Lladdr, Dev: it.Dev, State: state})
	}
	slices.SortFunc(ns, func(a, b Neigh) int {
		if c := strings.Compare(a.Dev, b.Dev); c != 0 {
			return c
		}
		return strings.Compare(a.Dst, b.Dst)
	})
	return ns, nil
}

// CountByDev はインタフェースごとの機器数。IPv4 と IPv6 で同じ MAC が並ぶので MAC で数える
func CountByDev(ns []Neigh) map[string]int {
	seen := map[string]map[string]bool{}
	for _, n := range ns {
		if seen[n.Dev] == nil {
			seen[n.Dev] = map[string]bool{}
		}
		seen[n.Dev][n.Lladdr] = true
	}
	counts := make(map[string]int, len(seen))
	for dev, macs := range seen {
		counts[dev] = len(macs)
	}
	return counts
}
