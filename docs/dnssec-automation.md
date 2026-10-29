# DNSSEC 鍵更新の自動化

## 結論

**署名（RRSIG）の更新と ZSK のロールオーバーは自動化できます。**
**KSK のロールオーバーは、ゾーン側の準備までなら自動化できますが、最後の親ゾーンの DS 更新だけは
この権威サーバの外側の操作**（レジストラ API、親ゾーン管理者、RFC 8078 の CDS を消費する親など）
が必要です。したがって「完全に自己完結した全自動」は、親が CDS/CDNSKEY を自動処理しない限り無理です。

| 項目 | 自動化 | 親ゾーン操作 |
|---|---|---|
| RRSIG の再署名 | 可能 | 不要 |
| ZSK ロールオーバー | 可能 | 不要（DS は KSK を指す） |
| KSK の事前公開・二重署名 | 可能 | 不要 |
| 親 DS の切り替え | 条件付き | **必要** |
| KSK の退役 | 可能 | DS 切り替え後 |
| 鍵生成 | 可能（OpenSSL） | 不要 |

## 現状の実装

- `dnssec-key` / `--dnssec-key` で指定した **1 つの秘密鍵**を読み、ゾーンロード時に署名します。
- `validity` の既定値は 30 日です。
- `SIGHUP` でゾーンを再読み込みすると、同じ鍵で署名し直します。
- 自動タイマー、複数鍵、鍵ディレクトリ、CDS/CDNSKEY、親 DS 更新フックは未実装です。
- 同じ SOA シリアルで RRSIG だけが変わった再署名では、IXFR ジャーナルを保持するように
  しています。ただしセカンダリは SOA が同じだとリフレッシュで転送を要求しないため、
  新しい RRSIG を IXFR で配るにはシリアルを進める設計が必要です。
- 同じシリアルで RRSIG 以外のデータが変わった場合は、IXFR で表現できないため
  ジャーナルを破棄します。

## 提案する構成

### 鍵ディレクトリ

```text
keys/example.com/
  ksk-2026-01.pem       # flags 257 (SEP + Zone Key)
  ksk-2026-10.pem       # ロールオーバー中のみ
  zsk-2026-01.pem       # flags 256 (Zone Key)
  zsk-2026-04.pem       # ロールオーバー中のみ
  state                 # フェーズ、時刻、DS 待ち状態
```

- ファイル名の `ksk-` / `zsk-` でロールを判定。
- サーバはディレクトリ内の **公開中の全鍵**で署名します。
- DNSKEY RRset は KSK 群で、通常の RRset は ZSK 群で署名します（複数なら複数 RRSIG）。
- ロールオーバー中は新旧両方で署名し、DNSKEY にも両方を公開します。

### 状態機械

```text
idle
  -> zsk-prepublished    新 ZSK を追加、旧+新で署名
  -> zsk-active          旧 ZSK を削除
  -> idle

idle
  -> ksk-prepublished    新 KSK を追加、DNSKEY RRset を旧+新で署名
  -> ds-pending          親 DS の更新待ち（CDS/CDNSKEY を公開）
  -> ksk-active          旧 KSK を削除
  -> idle
```

### タイミング

TTL を `T` とします。

| フェーズ | 待ち時間 | 理由 |
|---|---|---|
| 新 DNSKEY の事前公開 | `max(2T, 1h)` | キャッシュされた DNSKEY を更新 |
| ZSK の二重署名 | `max(2T, 1h)` | 旧署名のキャッシュ切れ |
| KSK の DS 切り替え | 旧 DS の TTL | 古い DS を持つリゾルバの更新 |
| 旧 KSK の削除 | 新 DS の TTL | 新 DS の伝播 |
| RRSIG 再署名 | 有効期限の 1/3 前 | 期限切れ防止 |

## RRSIG の自動更新

1. タイマー（例: 毎日）で `auth-dns` を再読み込みし、同じ鍵で再署名。
2. 有効期限が近い場合だけ再署名する（`validity` と最終署名時刻を状態ファイルに保存）。
3. セカンダリにも配る場合は、SOA シリアルを 1 進めてから署名し、IXFR ジャーナルに
   RRSIG の差分を含める。シリアルを進めない場合、セカンダリは SOA が同じため
   リフレッシュで転送を要求せず、古い RRSIG を期限まで保持する。

現実的な運用は次のどちらかです。

- **プライマリのみ**: シリアルを進めずに再署名（セカンダリは AXFR 時に更新）。
- **セカンダリあり**: 再署名時にシリアルを進め、IXFR で RRSIG 差分を配る。

## ZSK ロールオーバー

1. 新しい ZSK を生成し、鍵ディレクトリに追加。
2. `SIGHUP` で再読み込み。DNSKEY に新 ZSK、各 RRset に旧+新の RRSIG。
3. `2T` 待つ。
4. 旧 ZSK を削除して `SIGHUP`。
5. 親 DS は変更不要（DS は KSK を指す）。

## KSK ロールオーバー

1. 新しい KSK を生成し、鍵ディレクトリに追加。
2. `SIGHUP`。DNSKEY RRset を旧+新 KSK で署名。
3. 親ゾーンに新しい DS を登録する。自動化する場合は CDS/CDNSKEY（RFC 8078）を
   公開し、親がそれを処理できる必要がある。
4. 旧 DS の TTL 以上待つ。
5. 旧 KSK を削除して `SIGHUP`。
6. 新しい DS の TTL 以上待って完了。

親が CDS を自動処理しない場合、3 はレジストラ API 呼び出し、または手動になります。
この部分だけは「サーバ内で完結」できません。

## systemd での運用例

```ini
# /etc/systemd/system/auth-dns.service
[Service]
ExecStart=/usr/local/bin/auth-dns serve -c /etc/auth-dns/auth-dns.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

```ini
# /etc/systemd/system/auth-dns-dnssec.service
[Service]
Type=oneshot
ExecStart=/usr/local/bin/auth-dns-dnssec-maintain --config /etc/auth-dns/auth-dns.conf
```

```ini
# /etc/systemd/system/auth-dns-dnssec.timer
[Timer]
OnCalendar=daily
Persistent=true
[Install]
WantedBy=timers.target
```

`auth-dns-dnssec-maintain` は次を行います。

- 署名期限の確認と再署名（必要ならシリアル更新）
- ZSK の寿命確認と段階的なロールオーバー
- KSK の寿命確認、CDS/CDNSKEY の公開、DS 待ち状態の管理
- 状態ファイルのアトミック更新とバックアップ
- 失敗時は旧鍵を残したままアラート

## CDS / CDNSKEY

KSK ロールオーバーを親に通知するには、子ゾーンに以下を公開します。

```text
CDS      <keytag> <algorithm> 2 <sha256>
CDNSKEY  <flags> 3 <algorithm> <public key>
```

親が RFC 8078 に対応していれば、DS 更新を自動化できます。
対応していない場合は、レジストラ API や親ゾーン管理者への通知が必要です。

## 実装フェーズ案

1. **鍵ディレクトリ + 複数鍵署名**
   - `dnssec-key-dir`
   - KSK/ZSK の役割
   - 複数 RRSIG / 複数 DNSKEY
2. **メンテナンス CLI**
   - `auth-dns dnssec status`
   - `auth-dns dnssec resign`
   - `auth-dns dnssec rollover-zsk`
   - `auth-dns dnssec rollover-ksk`
3. **CDS/CDNSKEY と親フック**
   - `--parent-hook`（レジストラ API 呼び出し）
   - DS 反映待ちの状態管理
4. **監視**
   - RRSIG 残り時間
   - DS と DNSKEY の一致
   - ロールオーバー滞留アラート

## セキュリティ

- 秘密鍵は 0600、専用ユーザー所有。
- 可能なら KSK はオフライン/HSM に置き、ZSK だけをオンラインにする。
- 鍵ディレクトリを Git やコンテナイメージに含めない。
- 状態ファイルと鍵のバックアップを取る。
- ロールオーバー中は旧鍵をすぐ消さない。
