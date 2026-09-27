package render

import (
	"strings"
	"testing"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/link"
)

func TestJSONEmptySlices(t *testing.T) {
	var b strings.Builder
	r := hynt.Report{Host: "box", IPsecDenied: true, Links: []link.Link{{Name: "eno1", Kind: link.Ethernet}}}
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "null") {
		t.Errorf("null が含まれる:\n%s", b.String())
	}
	if !strings.Contains(b.String(), `"ipsec_denied": true`) {
		t.Errorf("ipsec_denied が無い:\n%s", b.String())
	}
}
