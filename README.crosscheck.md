# CrossCheck Rust-for-Linux

Based on upstream Linux `v6.19-rc4` at commit
`9ace4753a5202b02191d54e9fdf7f9e3d02b85eb`, followed by four
consolidated commits:

1. Shared driver abstractions: ownership, DMA, IRQ, PCI, synchronization,
   supporting C helpers and module/macro integration.
2. VirtIO and network abstractions.
3. NVMe and balloon abstractions and NVMe core integration.
4. Final runtime improvements: block write-cache limits, VirtIO/network hot
   paths, NVMe request/DMA access, inline locking, PCI register leases and
   single-queue affinity.

All nine runtime kernel patches are already included. Do not apply them again.

## Build

Use Linux x86-64 with LLVM/Clang 21, Rust nightly-2025-12-01, bindgen 0.72.1,
pahole, make, flex, bison, libelf and OpenSSL development headers. From the
separate `crosscheck-artifacts` directory:

```sh
python3 experiments/runtime/scripts/build.py \
  --kernel-source ../crosscheck-rfl --jobs 2
```

This uses the artifact's kernel configuration and driver inputs, exports this
repository's committed HEAD, and builds under `experiments/runtime/build/`.
It does not install a host kernel. See `crosscheck-artifacts/environment/README.md`
for toolchain setup. Do not add `--apply-runtime-patches` with this source.

## Licensing

Existing authorship notices, SPDX identifiers, `COPYING` and `LICENSES/` apply.
The original project author is `leeehh <527317196@qq.com>`; runtime changes
retain their existing attribution. Consolidation commits identify the packaging
author and do not transfer copyright or claim original authorship.
