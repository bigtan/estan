use std::env;
use std::path::Path;

#[cfg(feature = "uploader-baidu")]
#[test]
#[ignore]
fn real_upload_baidu() {
    use estan::uploader::BaiduPanUploader;

    let app_key = env::var("BAIDU_APP_KEY").expect("BAIDU_APP_KEY missing");
    let app_secret = env::var("BAIDU_APP_SECRET").expect("BAIDU_APP_SECRET missing");
    let dest_path = env::var("BAIDU_DEST_PATH").expect("BAIDU_DEST_PATH missing");
    let file_path = env::var("UPLOAD_TEST_FILE").expect("UPLOAD_TEST_FILE missing");
    let config_path = env::var("BAIDU_CONFIG_PATH").ok().map(Into::into);

    assert!(Path::new(&file_path).is_file());

    let mut uploader = BaiduPanUploader::new(app_key, app_secret, config_path).unwrap();
    let ok = uploader.upload(&file_path, &dest_path).unwrap();
    assert!(ok);
}

#[cfg(feature = "uploader-cloud189")]
#[test]
#[ignore]
fn real_upload_cloud189() {
    use estan::uploader::Cloud189Uploader;
    use std::sync::Once;
    use tracing_subscriber::fmt;

    let dest_path = env::var("CLOUD189_DEST_PATH").expect("CLOUD189_DEST_PATH missing");
    let file_path = env::var("UPLOAD_TEST_FILE").expect("UPLOAD_TEST_FILE missing");
    let config_path = env::var("CLOUD189_CONFIG_PATH").ok().map(Into::into);
    let username = env::var("CLOUD189_USERNAME").ok();
    let password = env::var("CLOUD189_PASSWORD").ok();
    let use_qr = env::var("CLOUD189_USE_QR")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    assert!(Path::new(&file_path).is_file());

    static INIT: Once = Once::new();
    INIT.call_once(|| {
        fmt::init();
    });

    println!(
        "Cloud189 upload test: file={}, dest={}, qr_login={}",
        file_path, dest_path, use_qr
    );

    if use_qr {
        println!("Cloud189 QR login enabled. Follow terminal prompts if any.");
    }

    if username.is_some() {
        println!("Cloud189 username provided via env.");
    } else {
        println!("Cloud189 username not set; will use QR login.");
    }

    println!("Initializing Cloud189 uploader...");
    let mut uploader = Cloud189Uploader::new(config_path, username, password, use_qr).unwrap();
    println!("Starting Cloud189 upload...");
    let ok = uploader.upload(&file_path, &dest_path).unwrap();
    println!("Cloud189 upload finished. ok={}", ok);
    assert!(ok);
}
