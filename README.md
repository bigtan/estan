# estan

Shared Rust library for common uploader and notifier components used across
`backup-to-baidu`, `cloud-uploader-rs`, and `cfmmc-crawler-rs`.

## Features

Enable only what you need:

- `uploader` (base)
- `uploader-baidu`
- `uploader-cloud189`
- `notify` (base)
- `notify-chanify`
- `notify-email`
- `notify-pushgo`

## Usage (Cargo.toml)

```toml
[dependencies]
estan = { path = "../estan", features = ["uploader-baidu", "notify-email"] }
```

For a private GitHub repo:

```toml
[dependencies]
estan = { git = "ssh://git@github.com/OWNER/estan.git", branch = "main", features = ["uploader-baidu", "notify-email"] }
```

## Modules

- `estan::uploader`
  - `Uploader` trait
  - `UploadManager`
  - `UploadContext`
  - `BaiduPanUploader` (feature `uploader-baidu`)
  - `Cloud189Uploader` (feature `uploader-cloud189`)
- `estan::notify`
  - `Notifier` trait
  - `NotificationManager`
  - `chanify::ChanifyNotifier` (feature `notify-chanify`)
  - `email::EmailNotifier` (feature `notify-email`)
  - `pushgo::PushgoNotifier` (feature `notify-pushgo`)

## Real Network Tests

See `tests/REAL_TESTS.md`.
