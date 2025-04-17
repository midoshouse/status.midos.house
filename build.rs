use {
    std::{
        env,
        fs::File,
        io::prelude::*,
        path::Path,
    },
    itertools::Itertools as _,
};

fn main() {
    // only do a full rebuild if the git commit hash changed (see https://github.com/rust-lang/cargo/issues/4213 and https://github.com/rust-lang/cargo/issues/5663)
    println!("cargo::rerun-if-changed=.git");
    let mut f = File::create(Path::new(&env::var_os("OUT_DIR").unwrap()).join("version.rs")).unwrap();
    let repo = gix::open(env!("CARGO_MANIFEST_DIR")).unwrap();
    let commit_hash = repo.head_id().unwrap();
    writeln!(&mut f, "pub const GIT_COMMIT_HASH: gix::ObjectId = gix::ObjectId::Sha1([{:#x}]);", commit_hash.as_bytes().iter().format(", ")).unwrap();
}
