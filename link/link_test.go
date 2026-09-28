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
 {"ifname":"wlan0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "addr_info":[{"family":"inet","local":"192.0.2.132","prefixlen":24,"scope":"global"},
               {"family":"inet6","local":"fe80::2","prefixlen":64,"scope":"link"}]},
 {"ifname":"tun0","flags":["POINTOPOINT","MULTICAST","NOARP","UP","LOWER_UP"],"operstate":"UNKNOWN",
  "linkinfo":{"info_kind":"tun","info_data":{"type":"tun"}},
  "addr_info":[{"family":"inet","local":"100.64.0.1","prefixlen":32,"scope":"global"}]},
 {"ifname":"docker0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "linkinfo":{"info_kind":"bridge"},
  "addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]},
 {"ifname":"veth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"operstate":"UP",
  "master":"docker0","linkinfo":{"info_kind":"veth"},"addr_info":[]},
 {"ifname":"eth0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"operstate":"DOWN","addr_info":[]}
]`

func TestParse(t *testing.T) {
	fs := fakeSysfs{
		tuns:  map[string]int{"tun0": 0x5001},
		wifis: map[string]bool{"wlan0": true},
		devs:  map[string]bool{"wlan0": true, "eth0": true},
	}
	got, err := parse([]byte(sample), fs)
	if err != nil {
		t.Fatal(err)
	}

	want := []Link{
		{Name: "docker0", Kind: Bridge, Impl: "bridge", State: "UP", Addrs: []string{"172.17.0.1/16"}},
		{Name: "eth0", Kind: Ethernet, State: "DOWN"},
		{Name: "tun0", Kind: VPN, Impl: "tun", State: "UNKNOWN", Addrs: []string{"100.64.0.1/32"}},
		{Name: "veth0", Kind: Virtual, Impl: "veth", State: "UP", Master: "docker0"},
		{Name: "wlan0", Kind: Wifi, State: "UP", Addrs: []string{"192.0.2.132/24"}},
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
