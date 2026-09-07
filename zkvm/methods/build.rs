use std::collections::HashMap;
use std::path::Path;

use risc0_build::{
    embed_methods, embed_methods_with_options, DockerOptionsBuilder, GuestOptionsBuilder,
};

// Build the zkVM guest.
//
// By default the guest is built reproducibly inside the pinned RISC Zero
// guest-builder Docker image, so the resulting `image_id` is DETERMINISTIC on
// any machine (the non-Docker `embed_methods()` path embeds the host build path,
// which makes the id environment-specific). Requires Docker.
//
// Set RISC0_SKIP_DOCKER=1 for a fast local build when you do not need the
// canonical image_id (the id will then differ from the shipped artifacts).
fn main() {
    if std::env::var_os("RISC0_SKIP_DOCKER").is_some() {
        embed_methods();
        return;
    }

    // risc0's reproducible build runs `docker build --output ...`, a BuildKit feature.
    // Force BuildKit on so the build works regardless of the host's Docker default
    // (legacy builder rejects `--output`). Requires the buildx plugin to be installed.
    std::env::set_var("DOCKER_BUILDKIT", "1");

    // Mount the whole zkVM workspace (the parent of this `methods` crate) at /src
    // in the container, so the guest's `gps-core = { path = "../../gps-core" }`
    // dependency resolves inside the build.
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let root_dir = Path::new(&manifest_dir).parent().unwrap().to_path_buf();

    let docker = DockerOptionsBuilder::default()
        .root_dir(root_dir)
        .build()
        .unwrap();

    let guest_opts = GuestOptionsBuilder::default()
        .use_docker(docker)
        .build()
        .unwrap();

    let mut opts = HashMap::new();
    opts.insert("gps-guest", guest_opts);
    embed_methods_with_options(opts);
}
