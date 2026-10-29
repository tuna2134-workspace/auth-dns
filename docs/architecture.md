# アーキテクチャ

## 全体像

```text
                    +---------------------+
  zone file  ---->  |  lexer              |  src/zone/lexer.zig
                    |  token stream       |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |  parser             |  src/zone/parser.zig
                    |  AST                |  src/zone/ast.zig
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |  semantic analyser  |  src/zone/sema.zig
                    |  $ORIGIN/$TTL/      |
                    |  $INCLUDE/名前解決/  |
                    |  RDATA 変換          |
                    +----------+----------+
                               |
                               v
                    +---------------------+
                    |  Zone.build         |  src/zone/zone.zig
                    |  正規化/整列/RRset  | 
                    |  索引/NSEC 索引      |
                    +----------+----------+
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
    +-------------------+             +-------------------+
    | query responder   |             | transfer builder  |
    | src/server/query  |             | src/zone/transfer |
    +---------+---------+             +---------+---------+
              |                                 |
              v                                 v
    +---------------------------------------------------+
    | UDP / TCP server (src/server/server.zig)           |
    +---------------------------------------------------+
```

## レイヤごとの責務

### lexer (`src/zone/lexer.zig`)

- BIND マスターファイルの字句解析。
- 空白・改行・`;` コメント・`(` `)` 継続・引用符・`\DDD`/`\X` を処理。
- 論理行の先頭が空白かどうかを `leading_ws` として記録し、オーナー省略の判定に使う。
- エスケープは**保持**する。名前では `\.` と区切りが違うため、文字列では `\DDD` を
  デコードする必要がある。

### parser (`src/zone/parser.zig`) と AST (`src/zone/ast.zig`)

- 1 論理行 = 1 ノード。
- ノードは `record` / `origin` / `ttl` / `include`。
- レコードは `owner?`, `ttl?`, `class?`, `rtype`, `rdata: []Token`, `line`。
- `$GENERATE` は構文糖としてパーサで展開し、通常の record ノードにする。
- `$INCLUDE` はファイル I/O とスコープ管理が必要なので AST ノードとして残す。
- 名前解決・TTL 解釈は行わない。

### 意味解析 (`src/zone/sema.zig`)

- `$ORIGIN` の更新、相対名の解決、`@` の解決。
- `$TTL` と TTL 省略時の既定値（`$TTL` → 前回 TTL → 3600、SOA があれば minimum）。
- `$INCLUDE` の再帰読み込み。終了時に原点・TTL・前回オーナーを復元。
- RDATA トークンを `src/dns/rdata.zig` でワイヤ形式に変換。
- 検証:
  - SOA は apex に 1 つ、NS は apex に 1 つ以上。
  - レコードはゾーン内。
  - CNAME と他のデータの共存禁止（RFC 2181 §10.1）。
  - ワイルドカードは左端ラベルのみ。
  - クラスはゾーンと一致。
- 出力は `zone.Record` の配列（owner/rdata はアリーナ所有）。

### Zone (`src/zone/zone.zig`)

- レコードを RFC 4034 の正規順（owner の逆ラベル順、type、RDATA）でソート。
- `(owner, type)` ごとに RRset にまとめる。RRSIG は「covered type」ごとに別 RRset
  （RFC 4035 §2.2: RRSIG は通常の RRset ではない）。
- TTL は RRset の先頭を採用。異なる TTL は警告。
- 完全一致用の `index: owner -> []RRset index`、存在名（ENT 含む）の `names`、
  委任点の `delegations`、NSEC の canonical 順索引 `nsec_names`、
  NSEC3 の hashed owner 索引 `nsec3_names` / `nsec3_params` を構築。
- 構築後は不変。クエリはロックなしで読める（サーバ側で RwLock によりリロードと排他）。

### クエリ処理 (`src/server/query.zig`)

- 1 質問のみ受け付ける。QDCOUNT≠1 は FORMERR。
- EDNS(0):
  - OPT は additional に 1 つだけ。複数/誤配置は FORMERR。
  - VERSION>0 は BADVERS（header RCODE 0 + ext-RCODE 1）。
  - 応答サイズは `min(設定上限, max(512, クライアント CLASS))`。EDNS なしは 512。
  - DO=1 かつ署名済みゾーンなら RRSIG/NSEC を含める。
- ゾーン選択は最長一致。
- 委任:
  - 委任点以下は referral（AA=0、NS を authority、glue を additional）。
  - 委任点自身の DS だけは親側が権威回答（AA=1）。
- 完全一致:
  - CNAME は非 DNSSEC 型の問い合わせで CNAME + ターゲットを返す。
  - ANY はその名前の全 RRset（DO=0 では RRSIG/NSEC/NSEC3 を除く）。
  - 型なしは NODATA（SOA + NSEC）。
- 不一致:
  - RFC 4592 の closest encloser を求め、`*.<closest>` を合成。
  - ワイルドカードがなければ NXDOMAIN。
- 否定応答:
  - RFC 2308 の負の TTL = `min(SOA TTL, SOA MINIMUM)`。
  - NODATA は名前の NSEC、ENT は covering NSEC。
  - NXDOMAIN は QNAME を覆う NSEC と、closest encloser のワイルドカードを覆う NSEC。
  - ワイルドカード回答には QNAME の不存在を証明する NSEC を追加。
- additional:
  - NS/MX/SRV のターゲットについて、ゾーン内なら A/AAAA を追加。
- 応答が上限を超えたら TC=1 の最小応答（header + question + OPT）に作り直す。

### 転送 (`src/zone/transfer.zig`)

- `Packer` が 1 メッセージずつ `message.Builder` に詰める。
- 最初のメッセージだけ質問を含める（RFC 5936 は 2 通目以降 QDCOUNT=0 を許容）。
- 全メッセージで同じ ID、AA=1、TC=0。
- AXFR:
  - 先頭 SOA、本文（apex SOA を除く全 RRset）、末尾 SOA。
- IXFR:
  - リクエストの authority の最初の SOA からクライアントシリアルを取得。
  - 同一/新しい場合は現在の SOA 1 個。
  - ジャーナルに連続した差分があれば `current SOA, [old SOA, deleted, new SOA, added]*, current SOA`。
  - 未知のシリアルは AXFR にフォールバック。
- TSIG 使用時は `tsig.appendResponse` で各メッセージに署名。
  - 1 通目はリクエスト MAC、2 通目以降は直前の応答 MAC と timers-only 変数。
- セカンダリ側は `tsig.appendRequest` で要求を署名し、`tsig.verifyResponse` で
  1 通目（要求 MAC）と 2 通目以降（直前の応答 MAC + timers-only）を検証。

### ジャーナル (`src/zone/journal.zig`)

- `Delta { from_serial, to_serial, removed, added }`。
- リロード時に旧 Zone と新 Zone をフラット化し、`(owner, type, rdata, ttl)` で差分を取る。
  SOA は IXFR のフレーミングで表現するため差分から除外。
- メモリ上で最大 1024 差分 / 64 MiB。古いものから破棄。
- ディスク形式:
  - magic `ADNSJ1\n`
  - 各差分: from u32, to u32, removed_count u32, added_count u32
  - 各 RR: owner_len u8, owner, type u16, class u16, ttl u32, rdlen u16, rdata
- 再起動時に読み込み、最後の `to_serial` が現在のゾーンと一致しなければ破棄。

### セカンダリ (`src/server/secondary.zig`)

- プライマリへ TCP で IXFR（初回は AXFR）を要求。TSIG 設定時は要求を署名し、
  応答の MAC（AXFR/IXFR の連鎖を含む）を検証。
- 応答メッセージを解析し、RDATA 内の圧縮名を非圧縮の正規形に直して
  `Zone.build` で不変 Zone を構築。
- IXFR は「現在 SOA → 旧 SOA → 削除 → 新 SOA → 追加」の列として適用し、
  最後に新しい SOA を置く。
- `refresh` 間隔で SOA を確認し、TSIG 付き NOTIFY を受信したら即時リフレッシュ。
- 取得したゾーンはマスターファイルに書き戻し、再起動時に再利用。

### Dynamic Update (`src/server/update.zig`)

- RFC 2136 の prerequisite（yxdomain/nxdomain/yxrrset/nxrrset/値依存）と
  update（add/delete/delete-RRset/delete-name）を実装。
- 更新対象は不変 Zone をフラット化したレコード列。適用後に SOA シリアルを進め、
  一時ファイルへ書き出して `sema.load` で再検証・再署名する。
- 成功時は `journal.diff` で差分をジャーナルへ追加し、ゾーンファイルを
  アトミックに置き換え、`also-notify` へ NOTIFY を送る。
- 更新は排他ロックで直列化。

### DNSSEC 鍵管理 (`src/dnssec/keydir.zig`)

- `ksk-<unix>.pem` / `zsk-<unix>.pem` を列挙し、KSK(257)/ZSK(256) として読み込む。
- 複数 ZSK がある間は全 ZSK で署名（DNSKEY にも全部公開）。
- `dnssec-auto` 時は `openssl genpkey` で不足鍵を生成し、ZSK の寿命・伝播待ちを
  ファイル時刻から判断して追加・削除する。
- サーバの 1 秒タイマーが鍵変更を検出すると、SOA シリアルを進めて再署名し、
  ジャーナル・ゾーンファイル・NOTIFY を更新する。

### レート制限 (`src/server/ratelimit.zig`)

- 送信元 IP ごとのトークンバケット。`qps` と `burst` を設定。
- テーブルが上限を超えたら全消去してメモリを制限。
- UDP はドロップ、TCP は接続を閉じる。

### サーバ (`src/server/server.zig`)

- 起動時に設定の各ゾーンを `sema.load` で読み込む。
- UDP: リスナごとにスレッド。1 データグラムずつ処理。
- TCP: accept スレッド + 接続ごとのスレッド。
  - 2 バイト長プレフィックス、複数クエリ、パイプラインを処理。
  - 1 接続内の応答順は逐次処理で保たれる。
- `Io.RwLock`:
  - クエリ/転送構築は共有ロック。
  - SIGHUP リロードは排他ロック。
- SIGHUP:
  - 1 秒ごとにフラグを確認し、ゾーンを再読み込み。
- 1 秒ごとにセカンダリの refresh 期限を確認し、AXFR/IXFR を実行。
- NOTIFY（opcode 4）は TSIG を検証し、`allow-notify` ACL を確認して refresh を起動。
  プライマリは `also-notify` へ NOTIFY を送信（ターゲットごとに TSIG 署名可能）。
- Dynamic Update（opcode 5）は `allow-update` ACL を確認して適用。
- DNSSEC 自動運用: 1 秒ごとに鍵ディレクトリを確認し、RRSIG 更新期限または
  ZSK ロールオーバーがあれば再署名・シリアル更新・NOTIFY を行う。
  - シリアルが増えていれば差分をジャーナルに追加して保存。
  - 同一シリアルで内容が変わった場合はジャーナルを破棄（IXFR で表現不能）。

### DNSSEC (`src/dnssec/sign.zig`, `src/dnssec/openssl.zig`)

- `openssl.zig` は OpenSSL 3 の安定 ABI を手書き extern で宣言。
  `@cImport` は Zig 0.17 で廃止されたため。
- 鍵: PEM を `BIO_new_mem_buf` + `PEM_read_bio_PrivateKey` で読む。
- 公開鍵:
  - EC: `EVP_PKEY_get_octet_string_param("pub")` の非圧縮点から 0x04 を除く。
  - Ed25519: `EVP_PKEY_get_raw_public_key`。
  - RSA: `n`, `e` を BIGNUM で取得し DNSKEY 形式に組む。
- 署名:
  - ECDSA は DER を `d2i_ECDSA_SIG` で解析し、r||s 固定長に変換。
  - Ed25519 は raw 64 バイト。
  - RSA は PKCS#1 v1.5。
- `signZone`:
  - DNSKEY（KSK 257 + ZSK 256、同じ公開鍵）を追加。
  - 通常は NSEC チェーン（ENT には NSEC を作らない）。
  - `nsec3` 指定時は NSEC3PARAM + NSEC3 チェーン（ENT もハッシュ化、bitmap は空）。
  - `nsec3-opt-out` 時は insecure delegation を省略し、BIND 互換で全 NSEC3 に
    Opt-Out フラグを設定。DS 不在は covering NSEC3 + closest provable encloser で証明。
  - 各 RRset の canonical データを作り RRSIG を生成。
  - 委任点の NS は署名しない（親側は DS と NSEC のみ）。
- DS 生成は `ds` サブコマンドで行い、親ゾーンに登録できる。

## 並行性

- Zone は構築後不変。クエリは共有ロックの下で読み取り、応答バイト列をコピーして返す。
- 転送は共有ロックの下でメッセージを構築し、ロックを解放してから書き込む。
- リロードは排他ロックを取得し、旧 Zone を破棄して新しい Zone に置き換える。
- ジャーナルの追記と保存はリロード時のみ（排他ロック下）。

## エラー処理

- 構文エラーは `error.ParseFailed` と行番号。
- 意味エラーは `sema.Loader.err_line` に最後の行を保持。
- クエリの解析失敗は FORMERR、内部失敗は SERVFAIL。
- 転送の ACL 拒否は REFUSED、TSIG 失敗は NOTAUTH。
- サーバ起動時のゾーン読み込み失敗はプロセス終了（設定ミスを早期に検出）。
