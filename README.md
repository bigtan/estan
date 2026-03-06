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
  - `UploadAttempt`
  - `UploadResult`
  - `BaiduPanUploader` (feature `uploader-baidu`)
  - `Cloud189Uploader` (feature `uploader-cloud189`)
- `estan::notify`
  - `Notifier` trait
  - `NotificationManager`
  - `NotificationAttempt`
  - `NotificationResult`
  - `chanify::ChanifyNotifier` (feature `notify-chanify`)
  - `email::EmailNotifier` (feature `notify-email`)
  - `pushgo::PushgoNotifier` (feature `notify-pushgo`)

## API Notes

- `Uploader::upload()` now returns `Result<()>`. Success is `Ok(())`; all failures are reported as `Err`.
- `UploadManager::upload_file()` never stops at the first provider failure. It returns an `UploadResult`
  with one `UploadAttempt` per uploader, including error messages.
- `Notifier::send()` now returns `Result<()>`. `NotificationManager::send()` aggregates every channel into
  a `NotificationResult` instead of short-circuiting on the first error.
- `EmailNotifier` validates sender and recipient addresses and returns an error instead of panicking.

## Real Network Tests

See `tests/REAL_TESTS.md`.
