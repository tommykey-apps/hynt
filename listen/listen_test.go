package listen

import (
	"reflect"
	"testing"
)

// ss -H -tulnp の形。アドレスは文書用、プロセス名と pid は架空
const sample = `udp   UNCONN 0      0            0.0.0.0:5353       0.0.0.0:*    users:(("resolverd",pid=100,fd=12))
udp   UNCONN 0      0                  *:5353             *:*
tcp   LISTEN 0      4096      127.0.0.53%lo:53         0.0.0.0:*
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=200,fd=3),("sshd",pid=201,fd=3))
tcp   LISTEN 0      128             [::]:22            [::]:*
tcp   LISTEN 0      4096   [2001:db8::10]:8080          [::]:*
tcp   LISTEN 0      4096    192.0.2.10:8080       0.0.0.0:*
tcp   LISTEN 0      4096    192.0.2.10:8080       0.0.0.0:*
udp   UNCONN 0      0     [fe80::1]%eth0:546           [::]:*
`

func TestParse(t *testing.T) {
	got, err := parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	want := []Socket{
		{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "sshd"},
		{Proto: "tcp", Addr: "::", Port: 22},
		{Proto: "tcp", Addr: "127.0.0.53", Port: 53, Dev: "lo"},
		{Proto: "udp", Addr: "fe80::1", Port: 546, Dev: "eth0"},
		{Proto: "udp", Addr: "*", Port: 5353},
		{Proto: "udp", Addr: "0.0.0.0", Port: 5353, Process: "resolverd"},
		{Proto: "tcp", Addr: "192.0.2.10", Port: 8080}, // 同じ行が 2 つあっても 1 つ
		{Proto: "tcp", Addr: "2001:db8::10", Port: 8080},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
}

func TestParseBroken(t *testing.T) {
	if _, err := parse([]byte("tcp LISTEN 0 128 nonsense 0.0.0.0:*\n")); err == nil {
		t.Error("読めないアドレスでエラーにならない")
	}
}
