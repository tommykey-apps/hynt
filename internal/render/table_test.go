package render

import (
	"strings"
	"testing"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/link"
	"github.com/tommykey-apps/hynt/neigh"
	"github.com/tommykey-apps/hynt/route"
)

func TestTable(t *testing.T) {
	r := hynt.Report{
		Links: []link.Link{
			{Name: "eth0", Kind: link.Ethernet, State: "DOWN"},
			{Name: "tun0", Kind: link.VPN, Impl: "tun", State: "UNKNOWN", Addrs: []string{"100.64.0.1/32"}},
			{Name: "wlan0", Kind: link.Wifi, State: "UP", Addrs: []string{"192.0.2.132/24", "2001:db8::10/64"}},
		},
		Routes: []route.Route{
			{Dst: "100.64.0.2", Dev: "tun0", Table: "52"},
			{Dst: "default", Gateway: "192.0.2.1", Dev: "wlan0", Table: "main"},
			{Dst: "192.0.2.0/24", Dev: "wlan0", Table: "main"},
		},
		Neighs: []neigh.Neigh{
			{Dst: "192.0.2.1", Lladdr: "02:00:00:00:00:01", Dev: "wlan0", State: "REACHABLE"},
		},
		IPsecDenied: true,
	}
	var b strings.Builder
	if err := Table(&b, r); err != nil {
		t.Fatal(err)
	}
	want := `IF       KIND      STATE    NEIGH  ADDR             DST           VIA        TABLE
eth0     ethernet  DOWN     0      -                -             -          -
tun0     vpn tun   UNKNOWN  0      100.64.0.1/32    100.64.0.2    -          52
wlan0    wifi      UP       1      192.0.2.132/24   default       192.0.2.1  main
                                   2001:db8::10/64  192.0.2.0/24  -          main
(ipsec)  ipsec     DENIED   -      -                -             -          -
`
	if b.String() != want {
		t.Errorf("got:\n%s\nwant:\n%s", b.String(), want)
	}
}
