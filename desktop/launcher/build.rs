fn main() {
    println!("cargo:rerun-if-changed=assets/rogue-agent.rc");
    println!("cargo:rerun-if-changed=assets/rogue-agent.ico");
    println!("cargo:rerun-if-changed=assets/rogue-agent.manifest");
    // Build scripts run on the host; embed resources whenever the *target* is
    // Windows, including MinGW cross-builds from Linux.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile("assets/rogue-agent.rc", embed_resource::NONE)
            .manifest_required()
            .expect("embed Windows resources");
    }
}
