package route

import (
	"reflect"
	"testing"
)

// ip -j route show table all の実出力を切り詰めたもの
const routesSample = `[
 {"dst":"100.64.0.2","dev":"tailscale0","table":"52","flags":[]},
 {"dst":"default","gateway":"192.0.2.1","dev":"wlp2s0","protocol":"dhcp","prefsrc":"192.0.2.132","metric":600,"flags":[]},
 {"dst":"192.0.2.0/24","dev":"wlp2s0","protocol":"kernel","scope":"link","prefsrc":"192.0.2.132","metric":600,"flags":[]},
 {"dst":"172.17.0.0/16","dev":"docker0","protocol":"kernel","scope":"link","prefsrc":"172.17.0.1","flags":[]},
 {"type":"local","dst":"192.0.2.132","dev":"wlp2s0","table":"local","protocol":"kernel","scope":"host","flags":[]},
 {"type":"broadcast","dst":"192.0.2.255","dev":"wlp2s0","table":"local","protocol":"kernel","scope":"link","flags":[]},
 {"dst":"fd7a:115c:a1e0::/48","dev":"tailscale0","table":"52","metric":1024,"flags":[],"pref":"medium"},
 {"dst":"fe80::/64","dev":"wlp2s0","protocol":"kernel","metric":1024,"flags":[],"pref":"medium"},
 {"dst":"default","gateway":"fe80::0:ff:fe00:1","dev":"wlp2s0","protocol":"ra","metric":600,"flags":[],"pref":"medium"},
 {"type":"multicast","dst":"ff00::/8","dev":"wlp2s0","table":"local","protocol":"kernel","metric":256,"flags":[],"pref":"medium"}
]`

func TestParseRoutes(t *testing.T) {
	got, err := parseRoutes([]byte(routesSample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Route{
		{Dst: "172.17.0.0/16", Dev: "docker0", Table: "main"},
		{Dst: "100.64.0.2", Dev: "tailscale0", Table: "52"},
		{Dst: "fd7a:115c:a1e0::/48", Dev: "tailscale0", Table: "52", Metric: 1024},
		{Dst: "default", Gateway: "192.0.2.1", Dev: "wlp2s0", Table: "main", Metric: 600},
		{Dst: "default", Gateway: "fe80::0:ff:fe00:1", Dev: "wlp2s0", Table: "main", Metric: 600},
		{Dst: "192.0.2.0/24", Dev: "wlp2s0", Table: "main", Metric: 600},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

const rulesSample = `[
 {"priority":32766,"src":"all","table":"main"},
 {"priority":0,"src":"all","table":"local"},
 {"priority":5250,"src":"all","fwmark":"0x80000","fwmask":"0xff0000","action":"unreachable"},
 {"priority":5270,"src":"all","table":"52"},
 {"priority":32765,"not":null,"src":"all","fwmark":"0x1","table":"100"},
 {"priority":32764,"src":"all","table":"main","suppress_prefixlen":0}
]`

func TestParseRules(t *testing.T) {
	zero := 0
	got, err := parseRules([]byte(rulesSample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Rule{
		{Priority: 0, Selector: "from all", Table: "local"},
		{Priority: 5250, Selector: "from all fwmark 0x80000/0xff0000", Action: "unreachable"},
		{Priority: 5270, Selector: "from all", Table: "52"},
		{Priority: 32764, Selector: "from all", Table: "main", SuppressPrefixlen: &zero},
		{Priority: 32765, Selector: "not from all fwmark 0x1", Table: "100"},
		{Priority: 32766, Selector: "from all", Table: "main"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}
