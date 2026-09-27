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

// GoReleaser が -X main.version=v1.2.3 で埋める。go run のときは dev
var version = "dev"

func main() {
	asJSON := flag.Bool("json", false, "JSON で出す")
	showVersion := flag.Bool("version", false, "版を出す")
	flag.Parse()
	if *showVersion {
		fmt.Println("hynt", version)
		return
	}

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
