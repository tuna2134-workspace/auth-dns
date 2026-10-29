# RFC 準拠メモ

このサーバは RFC 1035 を基礎に、RFC Editor が示す更新 RFC のうち権威サーバに
関係するものを実装しています。以下は実装上の判断と、意図的に未実装の項目です。

## メッセージと名前

- **RFC 1035 §4.1**: 12 バイトヘッダ、QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT、
  QR/Opcode/AA/TC/RD/RA/Z/AD/CD/RCODE。
- **RFC 1035 §4.1.4**: 名前圧縮の受信に対応。ポインタは必ず前方（小さいオフセット）を
  指すものとし、ループ・前方ポインタ・不正ラベルタイプを拒否。
- **RFC 1035 §2.3.4 / RFC 2181 §11**: ラベル 63 オクテット、名前 255 オクテット。
- **RFC 4343**: 比較は ASCII の大文字小文字を無視。質問セクションは受信した
  オクテットをそのまま返す。ゾーン内の名前は小文字で保持。
- **RFC 2181 §5**: クラスは RR の同一性の一部。IN のみ提供し、他のクラスは REFUSED。
- **RFC 2181 §5.2**: RRset 内の TTL は先頭に統一。異なる TTL は警告して先頭を採用。
- **RFC 2181 §8**: TTL は 31 ビット（0..2^31-1）。
- **RFC 3597**: `TYPE####` / `CLASS####`、`\# length hex`。未知 RDATA は不透明に
  保存・転送し、圧縮しない。

## マスターファイル

- **RFC 1035 §5**: オーナー省略、`@`、相対名、括弧、引用符、`\DDD`、`;` コメント。
- BIND 拡張: `$TTL`, `$ORIGIN`, `$INCLUDE`, `$GENERATE`。
- TTL/クラスはどちらの順でも可。TTL は `1h30m` 形式。
- SOA の refresh/retry/expire/minimum は TTL 単位を受け付ける。
- `$INCLUDE` は取り込み後に原点・TTL・前回オーナーを復元。
- `$GENERATE` は `1-100`, `1-100/2`, `${offset,width,base}`（d/o/x/X）に対応。
- ロード時に以下を検証:
  - SOA は apex に 1 つ、NS は apex に 1 つ以上。
  - ゾーン外レコード禁止。
  - CNAME と他データの共存禁止、CNAME の重複禁止。
  - ワイルドカードは左端ラベルのみ。ワイルドカード NS は拒否。
  - クラスはゾーンと一致。

## 権威応答

- **RFC 1034 §4.3.2**: 完全一致、CNAME、委任、追加処理。
- **RFC 2308**: NXDOMAIN と NODATA を区別。どちらも AA=1、SOA を authority に含め、
  TTL は `min(SOA TTL, SOA MINIMUM)`。
- **RFC 4592**:
  - 完全一致がなければ closest encloser を求める。
  - `*.<closest>` が存在する場合だけ合成。
  - ENT は存在する名前として NODATA（NXDOMAIN ではない）。
  - 委任点以下では referral を優先し、ワイルドカードは使わない。
- **RFC 2181 §10.1**: CNAME は他のデータと共存しない。CNAME 問い合わせ以外では
  CNAME とチェーン先を返す。
- **RFC 8482**: ANY は全 RRset を返す実装（サブセット化はしていない）。
- **RFC 2181 §6**: referral は AA=0、NS を authority、glue を additional。
  NXDOMAIN/NODATA は AA=1。

## EDNS(0)（RFC 6891）

- OPT は additional に 1 つだけ。複数・answer/authority 内・root 以外の owner は FORMERR。
- CLASS は要求者の UDP ペイロードサイズ。512 未満は 512 として扱う。
- TTL は extended RCODE / version / flags（DO は bit 15）。
- VERSION>0 は BADVERS（header RCODE 0、OPT ext-RCODE 1）。
- 応答サイズは `min(設定上限, max(512, CLASS))`。EDNS なしは 512。
- 応答に収まらない場合は TC=1 の最小応答に作り直す。
- DO=1 かつ署名済みゾーンでは RRSIG/NSEC を含める。DO=0 でも明示的な
  QTYPE=RRSIG/DNSKEY/NSEC には答える。

## AXFR（RFC 5936）

- TCP のみ。UDP の AXFR は TC=1（ゾーンデータは返さない）。
- 最初のメッセージは質問 + 先頭 SOA。最後のメッセージは末尾 SOA。
- SOA は全体で 2 回だけ。中間メッセージに SOA を含めない。
- 全メッセージで同じ ID、AA=1、TC=0、NSCOUNT=0。
- 1 メッセージ 65535 バイトまで。TSIG 使用時は 65535-256 バイトで詰める。
- ACL は `allow-transfer` の先勝ち。デフォルトは拒否。
- TSIG 使用時は全メッセージに署名。

## IXFR（RFC 1995）

- リクエストの authority セクションの最初の SOA からクライアントシリアルを取得。
- 同一または新しいシリアル: 現在の SOA 1 個。
- ジャーナルに連続差分がある場合:
  `current SOA, [old SOA, deleted, new SOA, added]*, current SOA`。
- ジャーナルにないシリアル: AXFR にフォールバック（エラーにしない）。
- シリアル比較は RFC 1982 の 32 ビット巡回演算。
- UDP の IXFR は TC=1 で TCP 再試行を促す（実装簡略化）。

## TSIG（RFC 8945）

- RDATA: algorithm name, time signed (u48), fudge, MAC size/MAC, original ID,
  error, other len/other。
- リクエスト MAC: TSIG を除き ARCOUNT を 1 減らしたメッセージ + TSIG 変数。
- 応答 MAC: リクエスト MAC（u16 長 + 値）+ メッセージ + TSIG 変数。
- AXFR/IXFR の 2 通目以降: 直前の MAC + メッセージ + time/fudge のみ。
- 成功時の検証・署名を実装。MAC 不一致/未知鍵は NOTAUTH を返す（TSIG なし）。
- BADTIME は署名付き NOTAUTH（TSIG Error 18、Other Data にサーバ時刻）を返す。
- 鍵ごとの最新 Time Signed を保持し、fudge より古いリクエストをリプレイとして拒否。

## DNSSEC（RFC 4033/4034/4035）

- 署名アルゴリズム: 8 (RSASHA256), 13 (ECDSAP256SHA256),
  14 (ECDSAP384SHA384), 15 (ED25519)。
- DNSKEY は KSK(257) と ZSK(256) を同じ公開鍵で 2 つ公開。
  DNSKEY RRset は KSK、それ以外は ZSK で署名。
- RRSIG:
  - type covered, algorithm, labels, original TTL, expiration, inception,
    key tag, signer name, signature。
  - canonical 形式（owner 小文字、RDATA 小文字・非圧縮、RDATA 昇順）で署名。
  - ワイルドカードは labels を 1 減らす。
- NSEC:
  - 権威名のみチェーンに含める。ENT には NSEC を作らない。
  - 最後の NSEC は apex を指す。
  - 委任点は NS/DS/RRSIG/NSEC のビットマップ。委任 NS は署名しない。
- 否定証明:
  - NODATA: 名前の NSEC（ENT は covering NSEC）。
  - NXDOMAIN: QNAME を覆う NSEC + closest encloser のワイルドカードを覆う NSEC。
  - ワイルドカード回答: wildcard の NSEC + QNAME を覆う NSEC。
  - ワイルドカード NODATA: wildcard の NSEC + QNAME を覆う NSEC。
  - DS 不在: 委任点の NSEC。
- DS 生成: `auth-dns ds`。SHA-256 ダイジェスト。
- NSEC3:
  - NSEC3PARAM（alg 1, flags 0, iterations, salt）と NSEC3 チェーンを生成。
  - NSEC3 は ENT を含む全権威名をハッシュ化。ENT の type bitmap は空。
  - NODATA/NXDOMAIN/ワイルドカード/委任 DS 不在の NSEC3 否定証明。
  - opt-out は未実装。

## トランスポート

- **RFC 7766**: TCP は 2 バイト長プレフィックス、複数クエリ、接続再利用に対応。
  接続ごとにスレッドを立て、応答は逐次。
- アイドルタイムアウト、同時接続数制限、パイプラインの並列応答は未実装。
- UDP は 1 データグラム 1 クエリ。EDNS のサイズに従って TC を設定。

## 実装済みの拡張

- Dynamic Update（RFC 2136）: prerequisite、add、delete、delete-RRset、delete-name。
  TSIG/ACL、SOA シリアル更新、ジャーナル、DNSSEC 再署名、ゾーンファイル永続化。
- セカンダリ: AXFR/IXFR クライアント、SOA refresh、NOTIFY 受信、NOTIFY 送信。
- NSEC3 / NSEC3PARAM の署名生成と否定証明（opt-out を除く）。
- SVCB/HTTPS の主要パラメータのテキスト形式。
- TCP アイドルタイムアウト、同時接続数制限、送信元ごとのレート制限。
- TSIG BADTIME の署名付き応答と簡易リプレイキャッシュ。

## 意図的な未実装

- IQUERY（RFC 3425 で廃止）
- NSEC3 opt-out
- セカンダリからプライマリへの TSIG 付き XFR リクエスト
- DoT/DoH（libssl が必要）
- ビュー、RPZ、カタログゾーン、DNSSEC オンライン署名
- DNSSEC 鍵の自動ロールオーバー（設計のみ）
