//! HEAD regressions: existence and size without a body download.

use super::{fake_server, local_client};

#[test]
fn head_reports_an_existing_object_size() {
    const BODY: [u8; 42] = [b'x'; 42];
    let client = local_client(fake_server("200 OK", "", &BODY));
    assert_eq!(
        client.head("db/sqlite-1.sqlite3", || false).unwrap(),
        Some(42)
    );
}

#[test]
fn head_reports_a_missing_object_as_none() {
    let client = local_client(fake_server("404 Not Found", "", b""));
    assert_eq!(client.head("db/missing.sqlite3", || false).unwrap(), None);
}
