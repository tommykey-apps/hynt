package xfrm

import (
	"reflect"
	"testing"
)

// strongSwan が入れる policy の形 (in / fwd / socket を含む)。アドレスは文書用、spi は架空
const sample = `src 192.0.2.11/32 dst 198.51.100.0/24 
	dir out priority 374399 ptype main 
	tmpl src 192.0.2.11 dst 203.0.113.34
		proto esp spi 0x00001000 reqid 3 mode tunnel
src 198.51.100.0/24 dst 192.0.2.11/32 
	dir fwd priority 374399 ptype main 
	tmpl src 203.0.113.34 dst 192.0.2.11
		proto esp reqid 3 mode tunnel
src 198.51.100.0/24 dst 192.0.2.11/32 
	dir in priority 374399 ptype main 
	tmpl src 203.0.113.34 dst 192.0.2.11
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
		{Src: "192.0.2.11/32", Dst: "198.51.100.0/24", Gateway: "203.0.113.34", Mode: "tunnel"},
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
