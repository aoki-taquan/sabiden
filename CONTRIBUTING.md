# Contributing to sabiden

## エージェント開発ガイドライン

このプロジェクトは AI エージェントによる並列開発を前提としています。
人間とエージェントの両方が以下のルールに従うことで、スムーズな協調動作を実現します。

## ブランチ戦略

- `main` は保護ブランチ
- 機能ブランチ: `feature/<short-description>`
- バグ修正: `fix/<short-description>`
- ドキュメント: `docs/<short-description>`
- 1 PR = 1 トピック（小さく保つ）

## ワークフロー

```
1. Issue を作成 or アサイン
2. git worktree add で並列作業可能な環境を作る
3. 実装 + テスト追加
4. PR を出す（`auto-merge` ラベルを付けると CI 通過後自動マージ）
5. AI レビューを受ける（@code-reviewer エージェントが自動コメント）
6. CI 通過 + 承認 → squash merge
```

## コミットメッセージ規約

```
<type>: <subject>

<body>

Co-Authored-By: <agent-name> <email>
```

`type` は以下から:
- `feat`: 新機能
- `fix`: バグ修正
- `refactor`: リファクタリング
- `test`: テスト追加・修正
- `docs`: ドキュメント
- `chore`: ビルド・CI等
- `perf`: パフォーマンス改善

## コーディング規約

### Rust
- `cargo fmt` 必須（CI でチェック）
- `cargo clippy -- -D warnings` 必須
- `cargo test` 必須
- ドキュメンテーションコメントは `///` で
- public API は必ずドキュメント
- エラーは `anyhow::Result` または独自エラー型

### コメント
- WHY を書く、WHAT は書かない
- RFC 参照は明示する: `// RFC 3261 Section 8.1.1.7`
- TODO/FIXME はチケット番号付き

### テスト
- ユニットテストは同じファイル内 `#[cfg(test)] mod tests`
- 統合テストは `tests/` ディレクトリ
- SIP メッセージは実機キャプチャからテストベクタ化推奨

## SIP/RTP 実装上の注意

NTT ひかり電話特有の制約:
- **Via ヘッダに `rport` を付けない** (拒否される)
- **Session Timer (RFC 4028) 必須**
- **DSCP 32 (TOS 0x80) を SIP/RTP に設定**
- **G.711 μ-law のみ対応** (NGN 側)
- **DHCP Option 120 で SIP サーバ取得**

## エージェント協調ルール

### Worktree
他のエージェントの作業を踏まないように、それぞれ独立した worktree で作業:
```bash
git worktree add ../sabiden-feat-invite feature/invite-handler
```

### 競合回避
- 同じファイルを複数エージェントが同時に編集しない
- 共通インタフェース (trait, struct) は事前に決める
- `ARCHITECTURE.md` を真実の源とする

### PR レビュー
- 自分のPRはマージしない (CI 通過 + 別エージェント承認 + 人間最終確認)
- レビューコメントは具体的に (file:line で)
- LGTM の前にローカルでチェックアウトして動作確認推奨
