module github.com/tommykey-apps/hynt

go 1.27.1

// 開発機のネットワークの情報をテストに含むため撤回する
retract v0.1.0

// IPsec のテストに実環境の可能性があるアドレスを含むため撤回する
retract [v0.2.0, v0.4.0]
