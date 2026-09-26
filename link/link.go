package link

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

type Kind string

const (
	Ethernet Kind = "ethernet"
	Wifi     Kind = "wifi"
	VPN      Kind = "vpn"
	Bridge   Kind = "bridge"
	Virtual  Kind = "virtual"
)

type Link struct {
	Name  string
	Kind  Kind
	Impl  string
	State string
	Addrs []string
}

type sysfs interface {
	tunFlags(name string) (int, bool)
	wireless(name string) bool
	device(name string) bool
}

type realSysFs struct{}

func (realSysFs) tunFlags(name string) (int, bool) {
	b, err := os.ReadFile("/sys/class/net/" + name + "/tun_flags")
	if err != nil {
		return 0, false
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 0, 32)
	if err != nil {
		return 0, false
	}
	return int(v), true
}

func (realSysFs) wireless(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/wireless")
	return err == nil
}

func (realSysFs) device(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/device")
	return err == nil
}

type ipAddr struct {
	Iframe    string   `json:"iframe"`
	Operstate string   `json:"operstate"`
	Flags     []string `json:"flags"`
	Linkinfo  struct {
		Kind string `json:"kind"`
	} `json:"linkinfo"`
	AddrInfo []struct {
		Local     string `json:"local"`
		Prefixlen int    `json:"prefixlen"`
		Scope     string `json:"scope"`
	} `json:"addr_info"`
}

func List(ctx context.Context) ([]Link, error) {
	out, err := exec.CommandContext(ctx, "ip", "-j", "-d", "addr", "show").Output()
	if err != nil {
		return nil, fmt.Errorf("ip addr: %w", err)
	}
	return parse(out, realSysFs{})
}

func parse(raw []byte, fs sysfs) ([]Link, error) {
	var items []ipAddr
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(&items); err != nil {
		return nil, fmt.Errorf("unable to read ip addr json: %w", err)
	}
	var links []Link
	for _, it := range items {
		if slices.Contains(it.Flags, "LOOPBACK") {
			continue
		}
		l := Link{Name: it.Iframe, State: it.Operstate}
		l.Kind, l.Impl = classify(it.Iframe, it.Linkinfo.Kind, fs)
		for _, a := range it.AddrInfo {
			if a.Scope != "global" {
				continue
			}
			l.Addrs = append(l.Addrs, fmt.Sprintf("%s/%d", a.Local, a.Prefixlen))
		}
		links = append(links, l)
	}
	slices.SortFunc(links, func(a, b Link) int { return strings.Compare(a.Name, b.Name) })
	return links, nil
}

func classify(name, kind string, fs sysfs) (Kind, string) {
	switch kind {
	case "wireguard", "ovpn", "ppp", "xfrm":
		return VPN, kind
	case "tun":
		if f, ok := fs.tunFlags(name); ok && f&0x2 != 0 {
			return VPN, "tap"
		}
		return VPN, "tun"
	case "bridge":
		return Bridge, kind
	case "":
		if !fs.device(name) {
			return Virtual, ""
		}
		if fs.wireless(name) {
			return Wifi, ""
		}
		return Ethernet, ""
	default:
		return Virtual, kind
	}
}
