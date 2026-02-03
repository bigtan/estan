#[cfg(feature = "notify-chanify")]
#[test]
#[ignore]
fn real_notify_chanify() {
    use estan::notify::chanify::ChanifyNotifier;
    use estan::notify::Notifier;
    use std::env;

    let url = env::var("CHANIFY_URL").expect("CHANIFY_URL missing");
    let token = env::var("CHANIFY_TOKEN").expect("CHANIFY_TOKEN missing");
    let notifier = ChanifyNotifier::new(url, token);
    let ok = notifier
        .send("estan notify test", "chanify test message")
        .unwrap();
    assert!(ok);
}

#[cfg(feature = "notify-email")]
#[test]
#[ignore]
fn real_notify_email() {
    use estan::notify::email::EmailNotifier;
    use estan::notify::Notifier;
    use std::env;

    let sender = env::var("EMAIL_SENDER").expect("EMAIL_SENDER missing");
    let password = env::var("EMAIL_PASSWORD").expect("EMAIL_PASSWORD missing");
    let recipient = env::var("EMAIL_RECIPIENT").expect("EMAIL_RECIPIENT missing");
    let smtp_host = env::var("EMAIL_SMTP_HOST").unwrap_or_else(|_| "smtp.qq.com".to_string());
    let smtp_port: u16 = env::var("EMAIL_SMTP_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(465);

    let notifier = EmailNotifier::with_smtp(sender, password, recipient, smtp_host, smtp_port);
    let ok = notifier
        .send("estan notify test", "email test message")
        .unwrap();
    assert!(ok);
}

#[cfg(feature = "notify-pushgo")]
#[test]
#[ignore]
fn real_notify_pushgo() {
    use estan::notify::pushgo::PushgoNotifier;
    use estan::notify::Notifier;
    use std::env;

    let url = env::var("PUSHGO_URL").expect("PUSHGO_URL missing");
    let api_token = env::var("PUSHGO_API_TOKEN").expect("PUSHGO_API_TOKEN missing");
    let hex_key = env::var("PUSHGO_HEX_KEY").expect("PUSHGO_HEX_KEY missing");
    let channel_id = env::var("PUSHGO_CHANNEL_ID").expect("PUSHGO_CHANNEL_ID missing");
    let password = env::var("PUSHGO_PASSWORD").expect("PUSHGO_PASSWORD missing");
    let icon = env::var("PUSHGO_ICON").ok();
    let image = env::var("PUSHGO_IMAGE").ok();

    let notifier = PushgoNotifier::new(
        url, api_token, hex_key, channel_id, password, icon, image,
    );
    let ok = notifier
        .send("estan notify test", "pushgo test message")
        .unwrap();
    assert!(ok);
}
