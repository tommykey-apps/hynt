// hynt は、ホストが繋がっているネットワークを VPN を含めて 1 つの表に出す
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/tommykey-apps/hynt"
	"github.com/tommykey-apps/hynt/internal/render"
)

func main() {
	asJSON := flag.Bool("json", false, "JSON で出す")
	flag.Parse()

	r, err := hynt.Collect(context.Background())
	if err == nil {
		if *asJSON {
			err = render.JSON(os.Stdout, r)
		} else {
			err = render.Table(os.Stdout, r)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hynt:", err)
		os.Exit(1)
	}
}
