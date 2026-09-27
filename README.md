# hynt

ホストがどのネットワークに繋がっているかを、VPN を含めて 1 つの表に出す CLI。

    hynt
    hynt --json

同じ収集処理を Go のライブラリとして使える。

    r, err := hynt.Collect(ctx)

## 導入

Linux (amd64 / arm64)。Releases から tar.gz を取って置く:

    curl -L https://github.com/tommykey-apps/hynt/releases/latest/download/hynt_$(curl -s https://api.github.com/repos/tommykey-apps/hynt/releases/latest | grep -Po '"tag_name": "v\K[^"]+')_linux_amd64.tar.gz | tar xz hynt
    sudo install -Dm755 hynt /usr/local/bin/hynt

Go が入っていれば:

    go install github.com/tommykey-apps/hynt/cmd/hynt@latest

`ip xfrm policy` (IPsec の行) と `nft list ruleset` (`--json` のファイアウォール) だけ root が要る。それ以外は一般ユーザーで動く。

仕様は `docs/SPEC.md`。
