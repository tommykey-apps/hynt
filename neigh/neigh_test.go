package neigh

import (
	"reflect"
	"testing"
)

// ip -j neigh show の実出力を切り詰めたもの
const sample = `[
 {"dst":"192.0.2.1","dev":"wlan0","lladdr":"02:00:00:00:00:01","state":["REACHABLE"]},
 {"dst":"192.0.2.195","dev":"wlan0","state":["FAILED"]},
 {"dst":"fe80::1","dev":"wlan0","lladdr":"02:00:00:00:00:01","router":null,"state":["STALE"]},
 {"dst":"2001:db8:1:0:0:ff:fe00:1","dev":"wlan0","lladdr":"02:00:00:00:00:01","router":null,"state":["REACHABLE"]},
 {"dst":"172.17.0.2","dev":"docker0","lladdr":"02:42:ac:11:00:02","state":["STALE"]},
 {"dst":"192.0.2.20","dev":"wlan0","lladdr":"11:22:33:44:55:66","state":["STALE"]}
]`

func TestParse(t *testing.T) {
	got, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Neigh{
		{Dst: "172.17.0.2", Lladdr: "02:42:ac:11:00:02", Dev: "docker0", State: "STALE"},
		{Dst: "192.0.2.1", Lladdr: "02:00:00:00:00:01", Dev: "wlan0", State: "REACHABLE"},
		{Dst: "192.0.2.20", Lladdr: "11:22:33:44:55:66", Dev: "wlan0", State: "STALE"},
		{Dst: "2001:db8:1:0:0:ff:fe00:1", Lladdr: "02:00:00:00:00:01", Dev: "wlan0", State: "REACHABLE"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	counts := CountByDev(got)
	if counts["wlan0"] != 2 || counts["docker0"] != 1 {
		t.Errorf("counts = %v, want wlan0:2 docker0:1", counts)
	}
}
