package main

import (
	"context"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/tommykey-apps/hynt/link"
)

func main() {
	links, err := link.List(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "hynt:", err)
		os.Exit(1)
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IF\tKIND\tSTATE\tADDR")
	for _, l := range links {
		for i := 0; i < max(len(l.Addrs), 1); i++ {
			head := "\t\t"
			if i == 0 {
				head = fmt.Sprintf("%s\t%s\t%s", l.Name, kindLabel(l), l.State)
			}
			addr := "-"
			if i < len(l.Addrs) {
				addr = l.Addrs[i]
			}
			fmt.Fprintf(w, "%s\t%s\n", head, addr)
		}
	}
	w.Flush()
}

func kindLabel(l link.Link) string {
	if l.Impl == "" || l.Impl == string(l.Kind) {
		return string(l.Kind)
	}
	return string(l.Kind) + " " + l.Impl
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
