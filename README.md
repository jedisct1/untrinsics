# Untrinsics

**Untrinsics** is a single-header, portable implementation of commonly used Intel intrinsics — especially for cryptographic operations like AES — in plain, portable C.

It's ideal for environments where hardware intrinsics are unavailable, like embedded systems, WebAssembly, or just cross-platform sanity.

**Header-only**
**No dependencies**
**Crypto-friendly**
**Bit-accurate with Intel’s original instructions**

---

## Features

- Drop-in replacements for a wide range of Intel intrinsics
- AES-specific instructions like `_mm_aesenc_si128`, `_mm_aesdec_si128`, `_mm_aeskeygenassist_si128`, etc.
- Implements `__m128i` with dual access as bytes, 32-bit words, and 64-bit words
- Bitwise ops, shifting, and shuffle operations
- Suitable for test suites and cross-platform builds

---

## Usage

Simply include the header in your project:

```c
#include "untrinsics.h"
```

That’s it. No linking, no build flags, no fuss.

---

## Why?

Because sometimes you want or need Intel-style cryptographic instructions without depending on a specific CPU or compiler. This is particularly useful for:

- Writing portable crypto test vectors
- Cross-platform development (e.g., targeting WebAssembly)
- Understanding how AES and its building blocks work internally
- Educational and debugging use

Unlike larger projects like SIMDe (SIMD Everywhere), which aim to comprehensively emulate a wide array of SIMD intrinsics across platforms, Untrinsics is deliberately focused and compact.

It targets a small set of the most commonly used operations in cryptographic implementations, making it lightweight, easy to audit and trivial to include in existing projects.

---

## Constant-Time Considerations

The emulated instructions include mitigations against timing-based side channels. However, this is a best-effort approach and does not replace hardware countermeasures or CPU-specific assembly code.

Because constant-time operation incurs significant performance costs, some AES instructions do not run in constant time by default; additional mitigations can be enabled by defining `UNTRINSICS_MITIGATE` before including this file. Note that these performance costs might lead users to disable cryptographic features entirely. If constant-time behavior is critical, effective mitigations—such as masking and bitslicing—should be applied at higher levels in your implementation.

---

## License

**Public Domain.**
No copyright.
No license.
No attribution required.
Use it however you like.

---

## Feedback

Open issues, suggest features, or just say hi. PRs are welcome!
