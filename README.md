# auth-dns

Zig 0.17 で実装した権威 DNS サーバです。ゾーンは BIND9 互換のマスターファイルで定義し、
UDP/TCP の権威応答、AXFR/IXFR、EDNS(0)、TSIG、NSEC を用いた DNSSEC 署名までを実装しています。
暗号処理は OpenSSL 3 の **libcrypto** にのみ依存します（libssl は使いません）。

## 特徴

- **RFC 1035 と主要な更新 RFC に準拠**
  - メッセージ形式、名前圧縮、TTL/クラス、CNAME、ワイルドカード（RFC 4592）、
    否定応答（RFC 2308）、未知 TYPE の RFC 3597 表現、EDNS(0)（RFC 6891）、
    TCP トランスポート（RFC 7766）、AXFR（RFC 5936）、IXFR（RFC 1995）、
    シリアル演算（RFC 1982）、TSIG（RFC 8945）。
- **BIND9 互換ゾーンファイル**
  - `$TTL` / `$ORIGIN` / `$INCLUDE` / `$GENERATE`
  - 括弧による複数行、`;` コメント、引用符、`\DDD` エスケープ、`@`、相対名、
    オーナー省略、TTL/クラスの順序自由、`\# length hex`。
  - A, AAAA, NS, SOA, CNAME, MX, TXT, PTR, SRV, CAA, NAPTR, HINFO,
    TLSA, SSHFP, DS, DNSKEY, RRSIG, NSEC, NSEC3/NSEC3PARAM, LOC, URI,
    CERT, WKS, EUI48/64, ZONEMD, CSYNC, RP, AFSDB, RT, KX など。
- **コンパイラ型のパイプライン**
  - `lexer -> parser -> AST -> 意味解析 -> 不変 Zone`。
    パーサは構文だけを扱い、`$ORIGIN`/`$TTL`/相対名解決は意味解析が行います。
- **AXFR / IXFR / セカンダリ**
  - TCP 上の複数メッセージ転送。AXFR は先頭と末尾が同一 SOA。
  - IXFR はメモリ内ジャーナル＋ディスク永続化。SIGHUP リロードで差分を生成。
  - TSIG 使用時は各メッセージに署名し、AXFR の MAC 連鎖（RFC 8945）に対応。
  - セカンダリモード（AXFR/IXFR クライアント、SOA refresh、NOTIFY 受信・送信）。
- **Dynamic Update（RFC 2136）**
  - prerequisite / add / delete / delete-RRset / delete-name、TSIG/ACL に対応。
  - 更新後に SOA シリアルを進め、ジャーナル・ゾーンファイル・DNSSEC 署名を更新。
- **NSEC3**
  - NSEC3PARAM / NSEC3 の生成、ハッシュチェーン、NODATA/NXDOMAIN/ワイルドカードの否定証明。
- **SVCB / HTTPS**
  - `alpn` / `port` / `ipv4hint` / `ipv6hint` / `ech` / `dohpath` / `mandatory` / `no-default-alpn`。
- **DNSSEC（オフライン署名）**
  - ECDSA P-256/P-384、Ed25519、RSA/SHA-256（アルゴリズム 13/14/15/8）。
  - DNSKEY（KSK+ZSK）、RRSIG、NSEC チェーン、DS 生成。
  - NXDOMAIN / NODATA / ENT / ワイルドカードの NSEC 証明。
  - `dnssec-verify` と `delv` で検証済み（統合テスト参照）。
- **TSIG**
  - HMAC-SHA1/256/384/512。リクエスト検証、応答署名、AXFR/IXFR の複数メッセージ署名。
  - BADTIME の署名付き応答と簡易リプレイキャッシュ。
- **運用**
  - TCP アイドルタイムアウト、同時接続数制限、送信元ごとのレート制限。
- **運用向け**
  - BIND 風の設定ファイル、ACL、SIGHUP によるゾーンリロード、チェック用 CLI。

## 必要環境

- Zig 0.17.0 以降
- OpenSSL 3.x の開発ファイル（`libcrypto`）
- Linux（`std.Io` のネットワーク実装を使用）

## ビルド

```sh
zig build
zig build test
./zig-out/bin/auth-dns version
```

> 注: グローバルキャッシュが読み取り専用の環境では
> `ZIG_GLOBAL_CACHE_DIR="$PWD/.zig-global-cache" zig build` を使ってください。

OpenSSL が標準以外の場所にある場合は、リンカの探索パスを設定してください。

```sh
LIBRARY_PATH=/opt/openssl/lib zig build
```

## クイックスタート

設定ファイルを使う場合:

```sh
./zig-out/bin/auth-dns serve -c examples/auth-dns.conf
```

CLI だけで起動する場合:

```sh
./zig-out/bin/auth-dns serve \
  -l 127.0.0.1:15353 \
  -z example.com=examples/example.com.zone \
  --allow-transfer any
```

問い合わせ:

```sh
dig @127.0.0.1 -p 15353 www.example.com A
dig @127.0.0.1 -p 15353 example.com MX
dig @127.0.0.1 -p 15353 missing.example.com A
dig @127.0.0.1 -p 15353 x.wild.example.com A
dig @127.0.0.1 -p 15353 x.sub.example.com A
```

ゾーンの検証:

```sh
./zig-out/bin/auth-dns checkzone -o example.com. -f examples/example.com.zone
```

## 設定ファイル

BIND 風の最小サブセットです。未知の文はエラーにします（ACL の書き忘れを黙って無視しないため）。

```conf
options {
    listen 127.0.0.1 port 15353;
    directory "examples";
    max-udp-size 1232;
};

key "xfr.example.com" {
    algorithm hmac-sha256;
    secret "BASE64SECRET";
};

zone "example.com" {
    type primary;
    file "example.com.zone";
    journal "example.com.jnl";
    allow-transfer { key "xfr.example.com"; 127.0.0.1; };
    dnssec-key "keys/example.com.pem";
    dnssec-flags 257;
};
```

- `listen` は複数指定できます。`127.0.0.1 port 15353` でも `127.0.0.1:15353` でも可。
- `directory` は `file` / `journal` / `dnssec-key` の相対パスの基準です。
- `allow-transfer` は先勝ちです。`any`, `none`, IPv4/IPv6 アドレス、CIDR、`key "name"` を指定できます。
- デフォルトの `allow-transfer` は **none** です。
- `type` は `primary` / `secondary`。セカンダリは `primary <addr>[:port];` と
  `allow-notify { ... };` を指定します。プライマリは `also-notify <addr>[:port];` で
  NOTIFY を送れます。
- `allow-update { ... };` で RFC 2136 の動的更新を許可します。

## ゾーンファイル

```zone
$TTL 3600
$ORIGIN example.com.
@   IN SOA ns1.example.com. hostmaster.example.com. (
        2024010101 1h 15m 1w 5m )
    IN NS  ns1.example.com.
    IN MX  10 mail.example.com.
ns1     IN A    192.0.2.53
mail    IN A    192.0.2.25
www     IN A    192.0.2.1
        IN AAAA 2001:db8::1
alias   IN CNAME www
*.wild  IN A    192.0.2.99
sub     IN NS   ns.sub.example.com.
ns.sub  IN A    192.0.2.100
```

対応する主な記法:

| 記法 | 内容 |
|---|---|
| `$TTL` / `$ORIGIN` | デフォルト TTL / 現在の原点 |
| `$INCLUDE file [origin]` | 取り込み。終了後は原点・TTL・前回オーナーを復元 |
| `$GENERATE 1-100 host$ A 192.0.2.$` | BIND の生成記法（`${offset,width,base}` 対応） |
| `( ... )` | 論理行の継続 |
| `"..."` / `\DDD` / `\X` | 文字列・任意オクテット |
| `\# len hex` | RFC 3597 の未知 TYPE |
| `@` / 相対名 / 末尾 `.` | 原点 / 原点付加 / 絶対名 |
| 行頭空白 | 前レコードのオーナーを継承 |

未知の TYPE は `TYPE1234` と `\#` で表現できます。未知の TYPE も `\#` 形式なら
そのまま保存・転送されます。SVCB/HTTPS は主要パラメータのテキスト形式にも対応しています。

## CLI

```text
auth-dns serve [options]
auth-dns checkzone --origin NAME --file FILE [--dnssec-key PEM]
auth-dns ds --key PEM --name NAME [--flags 257]
auth-dns version
```

`serve` の主なオプション:

| オプション | 説明 |
|---|---|
| `-c, --config FILE` | 設定ファイル |
| `-l, --listen ADDR:PORT` | 待ち受け（繰り返し可） |
| `-z, --zone NAME=FILE` | ゾーン（繰り返し可） |
| `--allow-transfer ACL` | 転送 ACL（カンマ区切り） |
| `--journal-dir DIR` | IXFR ジャーナルの保存先 |
| `--tsig NAME:ALG:SECRET` | TSIG キー（SECRET は base64） |
| `--dnssec-key PEM` | 全ゾーンを署名する鍵 |
| `--dnssec-flags N` | DNSKEY フラグ（既定 257） |
| `--max-udp-size N` | EDNS の UDP 上限（既定 1232） |

## AXFR / IXFR

```sh
# 許可された ACL から
dig @127.0.0.1 -p 15353 example.com AXFR

# TSIG 付き
dig @127.0.0.1 -p 15353 \
  -y hmac-sha256:xfr.example.com:BASE64SECRET \
  example.com AXFR

# 現在のシリアル（1 個の SOA が返る）
dig @127.0.0.1 -p 15353 -y ... example.com IXFR=2024010101

# 差分（ジャーナルがある場合）
dig @127.0.0.1 -p 15353 -y ... example.com IXFR=2024010100
```

ジャーナルを有効にした状態でゾーンファイルを書き換え、`SIGHUP` を送ると差分が記録されます。

```sh
kill -HUP "$(cat server.pid)"
```

ジャーナルは `--journal-dir` / `journal` で指定したパスに保存され、再起動後も IXFR に使えます。
未知のシリアル（ジャーナルにない）場合は AXFR にフォールバックします。

## DNSSEC

鍵の生成:

```sh
mkdir -p keys
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out keys/example.com.pem
```

DS の生成（親ゾーンに登録する値）:

```sh
./zig-out/bin/auth-dns ds -k keys/example.com.pem -n example.com
# example.com. 3600 IN DNSKEY 257 3 13 ...
# example.com. 3600 IN DS 47259 13 2 ...
```

NSEC3 で署名する場合:

```sh
./zig-out/bin/auth-dns serve -c examples/auth-dns.conf \
  --dnssec-nsec3 --dnssec-nsec3-salt aabbccdd --dnssec-nsec3-iterations 0
```

サーバ起動:

```sh
./zig-out/bin/auth-dns serve -c examples/auth-dns.conf
```

確認:

```sh
dig @127.0.0.1 -p 15353 +dnssec example.com DNSKEY
dig @127.0.0.1 -p 15353 +dnssec www.example.com A
dig @127.0.0.1 -p 15353 +dnssec missing.example.com A
```

`--dnssec-flags 257`（既定）では、同じ公開鍵を KSK(257) と ZSK(256) の 2 つの
DNSKEY として公開し、DNSKEY RRset を KSK、それ以外を ZSK で署名します。
これにより `dnssec-verify` が期待する KSK/ZSK 構成になります。

NSEC3 は `--dnssec-nsec3` / 設定の `dnssec-nsec3` で生成できます。
`dnssec-nsec3-iterations` と `dnssec-nsec3-salt`（16 進）でパラメータを指定します。
NSEC3 opt-out は未対応です。

## テスト

```sh
zig build test
./scripts/integration-test.sh
./scripts/advanced-test.sh
```

`integration-test.sh` は `dig` / `delv` / `dnssec-verify` を使い、以下を検証します。

- A, NXDOMAIN, NODATA, ワイルドカード, 委任, CNAME
- AXFR の先頭/末尾 SOA、TSIG AXFR、ACL 拒否
- DNSSEC の `RRSIG`、`delv` による A/NXDOMAIN/NODATA/ワイルドカードの完全検証
- `dnssec-verify` によるゾーン全体の署名検証
- SIGHUP リロード後の IXFR 差分

`advanced-test.sh` は NSEC3、Dynamic Update（nsupdate）、セカンダリ/NOTIFY/IXFR、
SVCB/HTTPS、TCP アイドル/レート制限、TSIG BADTIME を検証します。

NSD をセカンダリにした相互運用テスト（Docker が必要）:

```sh
./scripts/nsd-interop-test.sh
```

このテストは NSD 4.9.1 をコンテナで起動し、auth-dns から初回 AXFR（serial 100）、
SIGHUP 後の IXFR（serial 101）を受け取れること、変更・追加・削除が反映されることを
NOKEY と TSIG（hmac-sha256）の両方で確認します。詳細は
[integration/nsd/README.md](integration/nsd/README.md) を参照してください。

## 設計

詳細は [docs/architecture.md](docs/architecture.md) を参照してください。

```text
zone file
   |
   v
 lexer (src/zone/lexer.zig)
   |
   v
 parser (src/zone/parser.zig) ---> AST (src/zone/ast.zig)
   |
   v
 sema (src/zone/sema.zig: $ORIGIN/$TTL/$INCLUDE, 名前解決, RDATA 変換)
   |
   v
 raw records ---> Zone.build (src/zone/zone.zig: 並べ替え, RRset 化, 索引, NSEC 索引)
   |
   v
 不変 Zone ---> query (src/server/query.zig) / transfer (src/zone/transfer.zig)
```

- クエリ処理は Zone を読み取り専用で参照します。リロードは `Io.RwLock` の排他ロック、
  クエリは共有ロックで保護します。
- UDP はリスナごとに 1 スレッド、TCP は接続ごとに 1 スレッドです。
- ゾーンは起動時に署名し、クエリ時に署名処理を行いません（オフライン署名）。
- ジャーナルは `(from, to, removed, added)` の列で、IXFR の差分をそのまま表現します。

## RFC 準拠状況

| RFC | 内容 | 状態 |
|---|---|---|
| 1034 / 1035 | DNS の概念・実装 | 主要部分を実装 |
| 1876 | LOC | 実装 |
| 1982 | SOA シリアル演算 | 実装 |
| 1995 | IXFR | 実装（サーバ側） |
| 1996 | NOTIFY | 実装（セカンダリの refresh 起動、プライマリの also-notify） |
| 2136 | Dynamic Update | 実装（prerequisite/add/delete、TSIG） |
| 2181 | 仕様の明確化 | TTL/RRset/CNAME/クラスを実装 |
| 2308 | 否定キャッシュ | SOA 同梱・負の TTL を実装 |
| 3597 | 未知 TYPE | `\#` / `TYPE####` を実装 |
| 4033-4035 | DNSSEC | NSEC 署名・検証を実装 |
| 4343 | 大文字小文字 | 比較は無視、質問は元のケースを保持 |
| 4592 | ワイルドカード | closest encloser を実装 |
| 5936 | AXFR | TCP・複数メッセージ・先頭/末尾 SOA |
| 6891 | EDNS(0) | OPT/DO/BADVERS/サイズ処理 |
| 7766 | DNS over TCP | 2 バイト長、接続再利用、パイプライン |
| 8482 | ANY の最小化 | 全て返す（サブセット化は未実装） |
| 9460 | SVCB/HTTPS | 主要パラメータのテキスト形式 |
| 8945 | TSIG | HMAC、AXFR 連鎖、成功/一部エラー |

より詳細な RFC ノートは [docs/rfc-notes/](docs/rfc-notes/) にあります。

DNSSEC 鍵更新の自動化設計（RRSIG 更新・ZSK/KSK ロールオーバー・CDS）は
[docs/dnssec-automation.md](docs/dnssec-automation.md) にまとめています。

## 制限と今後の提案

- **DoT/DoH**: 現状は UDP/TCP のみ。TLS が必要なら libssl を追加し、`libcrypto` は
  そのまま使えます。`libssl` は TLS 終端のためだけに必要です。
- **NSEC3 opt-out**: NSEC3 は生成しますが、opt-out フラグ付きの委任省略には未対応です。
- **セカンダリの TSIG**: 受信側の TSIG 検証と応答署名は実装済みですが、セカンダリから
  プライマリへの AXFR/IXFR リクエストは現状 NOKEY です。TSIG を付ける場合は
  `secondary.zig` にリクエスト署名を追加してください。
- **DNSSEC 鍵更新の自動化**: 署名更新・ZSK/KSK ロールオーバーの設計は
  [docs/dnssec-automation.md](docs/dnssec-automation.md) にあります。サーバ内の
  自動スケジューラと CDS/CDNSKEY は未実装です。
- **SVCB/HTTPS の追加パラメータ**: 主要パラメータは対応していますが、将来の
  未知キーは `keyNNNNN` として保存・転送されます。
- **ビュー / RPZ / カタログゾーン**: 未実装です。
- **特権降下 / chroot / capabilities**: 53 番ポートで動かす場合は
  `CAP_NET_BIND_SERVICE` と専用ユーザーを推奨します。
- **メトリクス / 構造化ログ**: 現在は stderr への簡易ログのみです。

## libcrypto と libssl

権威 DNS サーバが必要とする暗号処理は、TSIG の HMAC、DNSSEC の署名・ハッシュ、
DS のダイジェストです。これらはすべて **libcrypto** に含まれます。
**libssl** は TLS のハンドシェイクとレコード層を提供するもので、DoT/DoH を実装するまで
リンクする必要はありません。本プロジェクトは `-lcrypto` のみをリンクします。

## ライセンス

特に指定していません。必要に応じて追加してください。
