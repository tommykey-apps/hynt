package firewall

import (
	"os"
	"reflect"
	"testing"
)

// testdata/ruleset.json は、架空の規則を名前空間 (unshare -rn) に読み込ませて nft -j list ruleset で出したもの。
// 表 filter: policy drop の input と jump 先の extra。表 other: 優先度 -10 の input と、対象外の output
func TestParse(t *testing.T) {
	raw, err := os.ReadFile("testdata/ruleset.json")
	if err != nil {
		t.Fatal(err)
	}
	got, err := parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []Chain{
		{Family: "inet", Table: "other", Name: "early", Hook: "input", Prio: -10, Policy: "accept", Rules: []Rule{
			{Protos: []string{"tcp"}, Dports: []PortRange{{22, 22}}, Verdict: "accept"}, // pkttype host は条件にしない
			{Unknown: []string{`meta iifname != "lo"`}, Protos: []string{"tcp"}, Dports: []PortRange{{6000, 6000}}, Verdict: "drop"},
		}},
		{Family: "inet", Table: "filter", Name: "input", Hook: "input", Policy: "drop", Rules: []Rule{
			{CtStates: []string{"established", "related"}, Verdict: "accept"},
			{CtStates: []string{"invalid"}, Verdict: "drop"},
			{Iifnames: []string{"lo"}, Verdict: "accept"},
			{Protos: []string{"icmp"}, Verdict: "accept"},
			{Protos: []string{"tcp"}, Dports: []PortRange{{22, 22}}, Verdict: "accept"},
			{Iifnames: []string{"eth0"}, Protos: []string{"tcp"}, Dports: []PortRange{{80, 80}, {443, 443}}, Verdict: "accept"}, // @allowed を開く
			{Iifnames: []string{"tun0"}, Protos: []string{"udp"}, Dports: []PortRange{{5353, 5353}, {41641, 41641}}, Verdict: "accept"},
			{Protos: []string{"tcp"}, Dports: []PortRange{{8000, 8100}}, Verdict: "accept"},
			{Verdict: "jump", Target: "extra"},
			{Verdict: "reject"},
		}},
		{Family: "inet", Table: "filter", Name: "extra", Rules: []Rule{
			{Unknown: []string{`ip saddr == {"prefix":{"addr":"192.0.2.0","len":24}}`}, Protos: []string{"tcp"}, Dports: []PortRange{{9000, 9000}}, Verdict: "accept"},
			{Iifnames: []string{"eth0"}, Protos: []string{"tcp"}, Dports: []PortRange{{631, 631}}, Verdict: "drop"},
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseVmap(t *testing.T) {
	raw := `{"nftables":[
 {"chain":{"family":"inet","table":"t","name":"in","type":"filter","hook":"input","prio":0,"policy":"accept"}},
 {"rule":{"family":"inet","table":"t","chain":"in","expr":[{"vmap":{"key":{"meta":{"key":"iifname"}},"data":{"set":[]}}}]}}
]}`
	got, err := parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if r := got[0].Rules[0]; r.Verdict != "unknown" || len(r.Unknown) != 1 {
		t.Errorf("vmap を読めない規則として残していない: %+v", r)
	}
}
