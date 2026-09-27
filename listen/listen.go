// Package listen は待ち受けているソケット (ss -tuln) を読む。外から入ってこられる口を知るため
package listen

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"os/exec"
	"slices"
	"strconv"
	"strings"
)

type Socket struct {
	Proto string `json:"proto"` // tcp / udp
	// Addr は待ち受けるアドレス。"0.0.0.0" と "::" と "*" はその系統のすべて
	Addr string `json:"addr"`
	Port int    `json:"port"`
	// Dev は特定の口に縛ったとき (127.0.0.53%lo の lo)。縛っていなければ空
	Dev string `json:"dev"`
	// Process はプロセス名。root でなければ他人のプロセスは空になる
	Process string `json:"process"`
}

func List(ctx context.Context) ([]Socket, error) {
	// Why not: ss に JSON 出力は無い (iproute2 7.2 時点)。-H で見出しを消したテキストを読む
	out, err := exec.CommandContext(ctx, "ss", "-H", "-tulnp").Output()
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}
	return parse(out)
}

// 1 行は「Netid State Recv-Q Send-Q Local Peer [Process]」。空白で区切る
func parse(raw []byte) ([]Socket, error) {
	var socks []Socket
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		s, ok := parseLocal(f[4])
		if !ok {
			return nil, fmt.Errorf("ss の待ち受けアドレスを読めない: %q", f[4])
		}
		s.Proto = f[0]
		if len(f) > 6 {
			s.Process = processName(f[6])
		}
		socks = append(socks, s)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(socks, func(a, b Socket) int {
		return cmp.Or(cmp.Compare(a.Port, b.Port), strings.Compare(a.Proto, b.Proto),
			strings.Compare(a.Addr, b.Addr), strings.Compare(a.Dev, b.Dev), strings.Compare(a.Process, b.Process))
	})
	// SO_REUSEPORT で同じ口を複数のソケットが待ち受けると同じ行が並ぶ
	return slices.Compact(socks), nil
}

// "0.0.0.0:22" "[::]:22" "*:22" "127.0.0.53%lo:53" "[fe80::1]%eth0:546" を読む
func parseLocal(s string) (Socket, bool) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return Socket{}, false
	}
	port, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return Socket{}, false
	}
	host, dev, _ := strings.Cut(s[:i], "%")
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return Socket{Addr: host, Port: port, Dev: dev}, true
}

// users:(("sshd",pid=1,fd=3),("sshd",pid=2,fd=3)) から最初の名前を取る
func processName(s string) string {
	_, rest, ok := strings.Cut(s, `(("`)
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, `"`)
	return name
}
