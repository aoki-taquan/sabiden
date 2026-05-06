use rand::Rng;

pub fn new_branch() -> String {
    let r: u64 = rand::thread_rng().gen();
    format!("z9hG4bK{:016x}", r)
}

pub fn new_call_id() -> String {
    let r: u64 = rand::thread_rng().gen();
    format!("{:016x}@hikari-sip", r)
}

pub fn new_tag() -> String {
    let r: u32 = rand::thread_rng().gen();
    format!("{:08x}", r)
}
