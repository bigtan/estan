# Real Network Tests

These tests perform real network calls. They are marked with `#[ignore]`
and must be run manually with environment variables configured.

## Run All Real Tests

```powershell
cargo test --features "uploader uploader-baidu uploader-cloud189 notify notify-email notify-pushgo notify-chanify" -- --ignored
```

## Run Only Notify Tests

```powershell
cargo test --features "notify notify-email notify-pushgo notify-chanify" -- --ignored real_notify
```

## Run Only Upload Tests

```powershell
cargo test --features "uploader uploader-baidu uploader-cloud189" -- --ignored real_upload
```

## Environment Variables

### Notify (Chanify)

- `CHANIFY_URL`
- `CHANIFY_TOKEN`

### Notify (Email)

- `EMAIL_SENDER`
- `EMAIL_PASSWORD`
- `EMAIL_RECIPIENT`
- `EMAIL_SMTP_HOST` (optional, default `smtp.qq.com`)
- `EMAIL_SMTP_PORT` (optional, default `465`)

### Notify (Pushgo)

- `PUSHGO_URL`
- `PUSHGO_API_TOKEN`
- `PUSHGO_HEX_KEY`
- `PUSHGO_CHANNEL_ID`
- `PUSHGO_PASSWORD`
- `PUSHGO_ICON` (optional)
- `PUSHGO_IMAGE` (optional)

### Upload (Shared)

- `UPLOAD_TEST_FILE` (path to a local small file)

### Upload (Baidu Pan)

- `BAIDU_APP_KEY`
- `BAIDU_APP_SECRET`
- `BAIDU_DEST_PATH`
- `BAIDU_CONFIG_PATH` (optional)

### Upload (Cloud189)

- `CLOUD189_DEST_PATH`
- `CLOUD189_CONFIG_PATH` (optional)
- `CLOUD189_USERNAME` (optional)
- `CLOUD189_PASSWORD` (optional)
- `CLOUD189_USE_QR` (optional, `1`/`true`)
