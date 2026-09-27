package xfrm

import (
	"reflect"
	"testing"
)

// strongSwan が入れる policy の実出力例 (in / fwd / socket を含む)
const sample = `src 10.22.46.11/32 dst 10.233.0.0/18 
	dir out priority 374399 ptype main 
	tmpl src 10.22.46.11 dst 10.22.46.34
		proto esp spi 0xce291c8a reqid 3 mode tunnel
src 10.233.0.0/18 dst 10.22.46.11/32 
	dir fwd priority 374399 ptype main 
	tmpl src 10.22.46.34 dst 10.22.46.11
		proto esp reqid 3 mode tunnel
src 10.233.0.0/18 dst 10.22.46.11/32 
	dir in priority 374399 ptype main 
	tmpl src 10.22.46.34 dst 10.22.46.11
		proto esp reqid 3 mode tunnel
src 2001:db8:a1::/64 dst 2001:db8:a2::/64 
	dir out priority 399999 ptype main 
	tmpl src 2001:db8:1::1 dst 2001:db8:2::1
		proto esp reqid 4 mode tunnel
src 0.0.0.0/0 dst 0.0.0.0/0 
	socket in priority 0 ptype main 
src 0.0.0.0/0 dst 0.0.0.0/0 
	socket out priority 0 ptype main 
`

func TestParse(t *testing.T) {
	got, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Policy{
		{Src: "10.22.46.11/32", Dst: "10.233.0.0/18", Gateway: "10.22.46.34", Mode: "tunnel"},
		{Src: "2001:db8:a1::/64", Dst: "2001:db8:a2::/64", Gateway: "2001:db8:2::1", Mode: "tunnel"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseEmpty(t *testing.T) {
	got, err := parse(nil)
	if err != nil || len(got) != 0 {
		t.Errorf("got %v, %v", got, err)
	}
}
