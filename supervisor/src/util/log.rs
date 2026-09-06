pub fn info(msg: &str) {
    println!("[supervisor] {msg}");
}

pub fn err(msg: &str) {
    eprintln!("[supervisor] {msg}");
}
