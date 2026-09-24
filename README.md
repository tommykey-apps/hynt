# hynt

ホストがどのネットワークに繋がっているかを、VPN を含めて 1 つの表に出す CLI。

    hynt
    hynt --json

同じ収集処理を Go のライブラリとして使える。

    r, err := hynt.Collect(ctx)

仕様は `docs/SPEC.md`。
