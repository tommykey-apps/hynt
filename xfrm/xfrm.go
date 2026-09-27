// Package xfrm は policy-based IPsec (strongSwan / libreswan) を読む。
// この方式の IPsec はインタフェースを作らないので、link や route には出てこない。
package xfrm

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"slices"
	"strings"
)

// ErrPermission は CAP_NET_ADMIN が無くて読めなかったとき
var ErrPermission = errors.New("ip xfrm policy は root 権限が要る")

// Policy は「Dst 宛ては Gateway と IPsec で結ぶ」という 1 件
type Policy struct {
	Src     string // ローカル側の範囲
	Dst     string // 相手側の範囲
	Gateway string // tmpl dst。トンネルの向こう端
	Mode    string // tunnel / transport
}

func List(ctx context.Context) ([]Policy, error) {
	// Why not: -j は xfrm では未対応 (iproute2 7.2 時点)。テキストを読む
	cmd := exec.CommandContext(ctx, "ip", "xfrm", "policy")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if strings.Contains(stderr.String(), "Operation not permitted") {
		return nil, ErrPermission
	}
	if err != nil {
		return nil, fmt.Errorf("ip xfrm policy: %w", err)
	}
	return parse(out)
}

// 出力は 1 policy が複数行に分かれるが、字句は「key value」の並びなので
// 「src」で始まる行を区切りにして 1 policy 分の字句をまとめてから読む
func parse(raw []byte) ([]Policy, error) {
	var ps []Policy
	var tokens []string
	flush := func() {
		if p, ok := fromTokens(tokens); ok {
			ps = append(ps, p)
		}
		tokens = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "src ") {
			flush()
		}
		tokens = append(tokens, strings.Fields(line)...)
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(ps, func(a, b Policy) int { return strings.Compare(a.Dst, b.Dst) })
	return ps, nil
}

func fromTokens(tokens []string) (Policy, bool) {
	var p Policy
	dir := ""
	inTmpl := false
	for i := 0; i+1 < len(tokens); i++ {
		key, val := tokens[i], tokens[i+1]
		switch key {
		case "tmpl":
			inTmpl = true
			continue // "tmpl" は値を持たない
		case "src":
			if !inTmpl {
				p.Src = val
			}
		case "dst":
			if inTmpl {
				p.Gateway = val
			} else {
				p.Dst = val
			}
		case "dir":
			dir = val
		case "mode":
			p.Mode = val
		}
		i++
	}
	// out だけ拾う。in / fwd は同じ組の裏側で、socket policy は dir を持たない
	if dir != "out" || p.Gateway == "" {
		return Policy{}, false
	}
	return p, true
}
