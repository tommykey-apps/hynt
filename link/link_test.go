package link

import (
	"reflect"
	"testing"
)

type fakeSysfs struct {
	tuns  map[string]int
	wifis map[string]bool
	devs  map[string]bool
}

func (f fakeSysfs) tunFlags(n string) (int, bool) { v, ok := f.tuns[n]; return v, ok }
func (f fakeSysfs) wireless(n string) bool        { return f.wifis[n] }
func (f fakeSysfs) device(n string) bool          { return f.devs[n] }

const sample = `[
 {"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"operstate":"UNKNOWN",
  "addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
 {"ifname":"wlp2s0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "addr_info":[{"family":"inet","local":"192.168.1.132","prefixlen":24,"scope":"global"},
               {"family":"inet6","local":"fe80::47e:3c2c:d191:83ae","prefixlen":64,"scope":"link"}]},
 {"ifname":"tailscale0","flags":["POINTOPOINT","MULTICAST","NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN",
  "linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}},
  "addr_info":[{"family":"inet","local":"100.105.101.45","prefixlen":32,"scope":"global"}]},
 {"ifname":"docker0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "linkinfo":{"info_kind":"bridge"},
  "addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]},
 {"ifname":"vethf76fd7f","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "linkinfo":{"info_kind":"veth"},"addr_info":[]},
 {"ifname":"eno1","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"operstate":"DOWN","addr_info":[]}
]`

func TestParse(t *testing.T) {
	fs := fakeSysfs{
		tuns:  map[string]int{"tailscale0": 0x5001},
		wifis: map[string]bool{"wlp2s0": true},
		devs:  map[string]bool{"wlp2s0": true, "eno1": true},
	}
	got, err := parse([]byte(sample), fs)
	if err != nil {
		t.Fatal(err)
	}

	want := []Link{
		{Name: "docker0", Kind: Bridge, Impl: "bridge", State: "UP", Addrs: []string{"172.17.0.1/16"}},
		{Name: "eno1", Kind: Ethernet, State: "DOWN"},
		{Name: "tailscale0", Kind: VPN, Impl: "tun", State: "UNKNOWN", Addrs: []string{"100.105.101.45/32"}},
		{Name: "vethf76fd7f", Kind: Virtual, Impl: "veth", State: "UP"},
		{Name: "wlp2s0", Kind: Wifi, State: "UP", Addrs: []string{"192.168.1.132/24"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %v, got, want", got, want)
	}
}

func TestClassify(t *testing.T) {
	fs := fakeSysfs{tuns: map[string]int{"tap0": 0x1002, "tun0": 0x1001}}
	cases := []struct {
		name, kind string
		wantKind   Kind
		wantImpl   string
	}{
		{"wg0", "wireguard", VPN, "wireguard"},
		{"ppp0", "ppp", VPN, "ppp"},
		{"tun0", "tun", VPN, "tun"},
		{"tap0", "tun", VPN, "tap"},
		{"cscotun0", "tun", VPN, "tun"}, // tun_flags が読めなくても tun 扱い
		{"dummy0", "dummy", Virtual, "dummy"},
		{"unknown0", "", Virtual, ""}, // device も wireless も無い
	}
	for _, c := range cases {
		k, impl := classify(c.name, c.kind, fs)
		if k != c.wantKind || impl != c.wantImpl {
			t.Errorf("%s: got (%s, %s) want (%s, %s)", c.name, k, impl, c.wantKind, c.wantImpl)
		}
	}
}
