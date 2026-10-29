# DNSSEC 署名更新と ZSK ロールオーバー

## 結論

**RRSIG の定期更新と ZSK ロールオーバーは、サーバ内で自動化されています。**
**KSK のロールオーバーは、最後の親 DS の更新だけがサーバ外の操作**になります。
親が CDS/CDNSKEY（RFC 8078）を自動処理しない限り、レジストラ API か手動対応が必要です。

| 項目 | 自動化 | 親ゾーン操作 |
|---|---|---|
| RRSIG の再署名 | 自動 | 不要 |
| ZSK の事前公開・二重署名・退役 | 自動 | 不要 |
| KSK の生成・公開 | 自動 | 不要 |
| 親 DS の切り替え | 未対応 | **必要** |
| CDS/CDNSKEY の公開 | 未対応 | — |

## 鍵ディレクトリ

```text
keys/example.com/
  ksk-1793280000.pem    # flags 257 (SEP + Zone Key)
  zsk-1793280000.pem    # flags 256 (Zone Key)
  zsk-1793280400.pem    # ロールオーバー中のみ（新 ZSK）
```

- ファイル名の `ksk-` / `zsk-` と Unix 時刻でロールと世代を判定。
- サーバはディレクトリ内の **公開中の全鍵**を読み、DNSKEY にすべて公開。
- DNSKEY RRset は KSK 群、通常 RRset と NSEC/NSEC3 は ZSK 群で署名。
- ロールオーバー中は新旧 ZSK の両方で署名するため、各 RRset に複数の RRSIG が付く。

設定:

```conf
zone "example.com" {
    type primary;
    file "example.com.zone";

    dnssec-key-dir "keys/example.com";
    dnssec-auto yes;

    dnssec-resign-interval 7d;   # RRSIG 再署名
    dnssec-zsk-lifetime   90d;   # 新 ZSK を出す間隔
    dnssec-propagation    1h;    # 旧 ZSK を残す時間
};
```

CLI:

```sh
auth-dns serve -l 127.0.0.1:5353 -z example.com=example.com.zone \
  --dnssec-key-dir keys/example.com --dnssec-auto \
  --dnssec-resign-interval 604800 \
  --dnssec-zsk-lifetime 7776000 \
  --dnssec-propagation 3600
```

`dnssec-auto` は鍵が無ければ `openssl genpkey` で P-256 の KSK/ZSK を生成します。
署名・検証そのものは libcrypto を直接使います。`openssl` コマンドは鍵生成時だけ必要です。

## 自動 RRSIG 更新

1. サーバは 1 秒ごとにメンテナンス時刻を確認。
2. `last_sign_ms` から `dnssec-resign-interval` 経過したら再署名。
3. 現在のゾーンから DNSSEC レコード（DNSKEY/RRSIG/NSEC/NSEC3/NSEC3PARAM）を除いた
   データを一時ファイルへ書き、SOA シリアルを 1 進める。
4. `sema.load` で再検証・再署名し、ジャーナルへ差分を追加、ゾーンファイルを
   アトミックに置換、`also-notify` へ NOTIFY を送る。
5. セカンダリは新しいシリアルを IXFR で取得し、新しい RRSIG を受け取る。

シリアルを進めるため、RRSIG 更新が IXFR/NOTIFY でセカンダリへ伝播します。

## ZSK ロールオーバー

サーバは鍵ディレクトリの時刻だけで状態を判断します（状態ファイル不要）。

```text
最新 ZSK の経過時間 < zsk-lifetime
  -> そのまま

最新 ZSK の経過時間 >= zsk-lifetime
  -> 新しい zsk-<now>.pem を生成
  -> 旧+新 ZSK で再署名（DNSKEY に両方、各 RRset に 2 つの RRSIG）
  -> SOA シリアル更新 + NOTIFY

最新 ZSK の経過時間 >= propagation かつ旧 ZSK が残っている
  -> 旧 ZSK ファイルを削除
  -> 新 ZSK だけで再署名
```

- `propagation` は「旧 DNSKEY/RRSIG がリゾルバキャッシュから消えるまで」の待ち時間。
- 目安は `max(2 * TTL, 1h)`。既定は 1 時間。
- ZSK の期限切れで緊急に切り替える場合も、この 2 段階を踏むため検証切れを避けられます。

## KSK

- KSK が無ければ自動生成し、DNSKEY RRset を KSK で署名。
- KSK のロールオーバーは未実装。親 DS の更新が必要なためです。
- 手動で KSK を追加する場合は、新しい `ksk-<timestamp>.pem` を置いて SIGHUP すると
  新旧 KSK で DNSKEY RRset を二重署名します。親 DS の切り替え後に旧 KSK を削除します。

## 単鍵モード

`dnssec-key` / `--dnssec-key` は従来の単鍵モードです。同じ鍵を KSK(257) と ZSK(256)
として公開します。自動更新・ロールオーバーは行いません。自動運用には
`dnssec-key-dir` + `dnssec-auto` を使ってください。

## systemd

サーバ内スケジューラを使うため、追加のタイマーは不要です。

```ini
[Service]
ExecStart=/usr/local/bin/auth-dns serve -c /etc/auth-dns/auth-dns.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
```

鍵ディレクトリはサーバユーザーだけが読めるようにします。

```sh
install -d -m 700 /etc/auth-dns/keys/example.com
chown -R auth-dns:auth-dns /etc/auth-dns/keys
```

## 監視

- `dig +dnssec DNSKEY` に KSK と ZSK が両方出るか。
- 各 RRset に有効な RRSIG があるか（`delv` / `dnssec-verify`）。
- `dig SOA` のシリアルが再署名で進んでいるか。
- 鍵ディレクトリに `zsk-*` が 2 つ残り続けていないか（伝播待ちの滞留）。
- RRSIG の expiration が十分先か。

## 制限

- 親 DS の自動更新、CDS/CDNSKEY の公開・処理は未実装。
- KSK の自動ロールオーバーは未実装（DS 待ちの状態管理が必要）。
- 鍵生成は `openssl` コマンドに依存。
- 自動再署名はゾーンファイルを書き換えます。読み取り専用のマウントでは使えません。
- 秘密鍵は 0600、専用ユーザー所有とし、Git やコンテナイメージに含めないでください。
