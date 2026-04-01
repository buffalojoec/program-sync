# SIMD-0460: Analysis of Stack Frame Gap Accesses

This report evaluates the potential impact of [SIMD-0460] ("Virtual Address
Space Adjustments") on existing Solana **mainnet-beta** programs.

Profiling results were obtained using Blueshift's [`program-sync`] tool.

**Date:** March 31, 2026
**Programs profiled:** 16,586 (4 failed to parse)

[SIMD-0460]: https://github.com/solana-foundation/solana-improvement-documents/pull/460
[`program-sync`]: https://github.com/blueshift-gg/program-sync

## Background

SIMD-0460 removes the 4 KiB unmapped "gap" between stack frames for
all programs, including existing SBPFv0 programs. Today each call depth
has a 4 KiB mapped frame followed by a 4 KiB unmapped gap; `r10` bumps
by 8 KiB on call. After SIMD-0460, frames are packed contiguously,
`r10` bumps by 4 KiB, and the upper half of the previous address space
becomes unmapped. Total mapped bytes stay the same.

Three risk categories exist:

1. **Gap accesses becoming valid** — offsets from `r10` that land in
   unmapped gap bands currently cause access violations. After gap
   removal, they silently succeed and hit adjacent frames' data.
2. **Cross-frame relative addressing** — offsets spanning multiple
   frames point to different physical memory when the frame stride
   changes from 8 KiB to 4 KiB.
3. **Stored `r10` (materialization)** — programs that persist the raw
   `r10` value to memory break because `r10`'s absolute value at any
   call depth changes.

## Methodology

Two detection tiers:

**Tier 1 — `offsets`**

Lightweight linear instruction scan. For every memory load/store
where the base register is `r10`, checks if the i16 offset lands in
a gap band. This pass does not catch derived pointers (e.g.
`mov64 r1, r10; add64 r1, off; stxdw [r1], r2`) — that requires
the Tier 2 intra-block propagation pass.

```
cargo run --release -- stack-gaps offsets --dir programs
```

**Tier 2 — `trace`**

Intra-basic-block constant propagation tracking `r10`-derived
registers. Catches patterns like
`mov64 r1, r10; add64 r1, -5000; stxdw [r1+0], r2` where the
effective offset lands in a gap but `r10` isn't the direct base.
Tracking resets at basic-block boundaries, so `add64 r10, -N`
adjustments in function prologues are not propagated across blocks.
This can only produce false *negatives* (missed gap accesses), never
false positives — and manual verification of the positive-gap V0
programs confirmed zero r10 adjustments exist in the affected
bytecode (see Frame Pointer Verification below).

```
cargo run --release -- stack-gaps trace --dir programs
```

**Gap bands from `r10`:**

| Band | Offset range | Description |
|------|-------------|-------------|
| Positive | `[0, +4095]` | Gap above the current frame (unmapped at any depth) |
| Negative | `[-8192, -4097]` | Gap below the current frame (unmapped at depth ≥ 1; below stack base at depth 0) |

## Results

### Tier 1 — Gap-Band Offsets

| Metric | Count |
|--------|-------|
| Programs flagged | **232** of 16,582 (1.4%) |
| — SBPFv0 | 189 |
| — SBPFv1 | 10 |
| — SBPFv2 | 33 |
| Total gap-band hits | 339,475 |

Only **SBPFv0** programs are at risk — V1+ already have gaps
disabled at the VM level
([`SBPFVersion::stack_frame_gaps()`][stack_frame_gaps] returns `true`
only for V0). The V1/V2 hits confirm the detector works but
represent no behavioral change.

[stack_frame_gaps]: https://github.com/anza-xyz/sbpf/blob/2c91f24c7bc717547db62961f53bab17dc467bf2/src/program.rs#L36-L39

**By gap band:**

| Band | Programs |
|------|----------|
| Negative only | 186 |
| Positive only | 45 |
| Both | 1 |

Of the 45 positive-only programs, 43 are V1/V2 (expected — they
were compiled for a gap-free layout where small positive offsets from
`r10` are normal). Only **3 V0 programs** have positive gap hits:
`ECQUvK1u`, `YDU46N7a`, and `JB3iGFee` (which also has negative
hits).

**Hits-per-program distribution:**

```
[1 .. 35,019]  █▁▁▁ ▁  ▁▁ ▁ ▁▁▁▁  ▁
```

The vast majority of flagged programs have a small number of hits.
The long tail is driven by a handful of large programs with extensive
compiler-generated spill code.

**Offset distribution:**

```
Negative [-8192 .. -4097]  ▁▁▁▁▁▁▁▁▁▂▂▂▃▃▄▃▅▆▇█  (56,661 hits)
Positive [+0 .. +4088]     █▄▂▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁  (282,814 hits)
```

Negative offsets cluster near `-4097` — just past the 4 KiB frame
boundary. These are oversized stack frames from compiler-generated
spill code. Positive offsets cluster near `+0` and are dominated by
V1/V2 programs using normal frame-relative addressing.

### Tier 2 — Derived Pointer Tracing

Tier 2's intra-block constant propagation found **76 derived
gap-band accesses** across programs already flagged by Tier 1. No new
programs were surfaced. Total gap-band hits: 328,927 (328,851 direct
+ 76 derived). The lower total compared to Tier 1 (339,475) is
expected — Tier 2 resolves effective offsets via register tracking,
reclassifying some Tier 1 hits that fall outside gap bands after
propagation.

This confirms that the compiler toolchain does not generate gap-band
accesses through derived registers — all gap-band memory operations
use `r10` directly as the base register.

### Frame Pointer Verification

The 3 V0 programs with positive gap hits (`ECQUvK1u`, `YDU46N7a`,
`JB3iGFee`) were checked for `r10` adjustments that could shift
effective offsets out of gap bands. Negative gap hits don't need this
check — those offsets already exceed the 4 KiB frame size, and any
r10 adjustment would push them further negative, not resolve them.
Both `add64` and `sub64` targeting `r10` returned **zero hits**
across all three programs — the raw instruction offsets are the true
effective offsets.

```
cargo run --release -- analyze --opcode add64 --count dst=10 --dir <programs>
cargo run --release -- analyze --opcode sub64 --count dst=10 --dir <programs>
```

This confirms that the flagged gap-band accesses genuinely target
unmapped memory and are not artifacts of frame pointer arithmetic.

### Risk Category #3 — Stored `r10`

Risk category #3 (programs persisting raw `r10` to memory) was
considered but not separately flagged. Storing `r10`-derived values
to memory is a universal compiler pattern — virtually all programs
pass intra-frame pointers as function arguments via
`mov r1, r10; add r1, -N; call fn`. A coarse-grained detector
cannot distinguish this routine behavior from genuinely risky
cross-region stores (e.g., writing a stack address into account
data). Manual inspection of the 3 positive-gap V0 programs
confirmed zero raw `r10` stores.

### RPC Usage

On-chain activity was queried for all 189 flagged SBPFv0 programs
via `getSignaturesForAddress` (up to 300 signatures per program).

| Last activity | Programs |
|---------------|----------|
| Today | 34 |
| Last 7 days | 10 |
| Last 30 days | 15 |
| Last 90 days | 26 |
| Last year | 43 |
| Over a year ago | 53 |
| No signatures | 0 |

Every flagged V0 program has on-chain transaction history — none
are abandoned. 34 were active within the last 24 hours. These are
real, deployed, invoked programs.

## Verdict

All 189 flagged SBPFv0 programs access **currently unmapped
memory** at the flagged instructions. The VM's translation-layer gap
enforcement ([`MemoryRegion::vm_to_host()`][vm_to_host]) returns
`AccessViolation` for gap addresses.

- **186 programs** — negative gap only. Offsets exceed the 4 KiB
  frame size (oversized stack frames, compiler-generated spill
  code). These are dead code paths — the instructions fault at any
  call depth under the current layout.
- **3 programs** — positive gap. Bytecode-level inspection confirmed
  zero `r10` adjustments in all three, so the raw offsets are the
  true effective offsets. These also fault today.
- **Derived pointer tracing** (Tier 2) surfaced no new at-risk
  programs beyond Tier 1.
- **All 189 programs** have on-chain transaction history; 34 were
  active today.

Under the current layout, the flagged instructions produce access
violations. If those code paths are reached today, they fail the
transaction. After SIMD-0460, the same instructions would silently
succeed — reading or writing adjacent frame data instead of
faulting. This replaces a visible crash with silent data corruption
for any transaction that exercises the affected paths.

The practical risk depends on whether these paths are reachable at
runtime. The 186 negative-gap programs use offsets that exceed the
4 KiB frame size, consistent with dead compiler-generated code. The
3 positive-gap programs have small offsets (+24 to +960) that could
plausibly be reached. On-chain transaction history confirms all 189
programs are deployed and invoked, but does not indicate whether the
flagged paths are exercised.

**Material risk is limited to 3 programs:**

- `ECQUvK1uZQjmqXZCPYN9EscUb2tS1kZ1gGVnn7r1Uc5f` — 1 hit at +24
- `YDU46N7aMNCzbDbmiUAugs2bikGCPdVMCwDevU5MPdB` — 1 hit at +24
- `JB3iGFeeT1K8mWmdVzypBowsyG28DYTSSvdQgcdTfF7P` — 6 hits at +952 to +960

[vm_to_host]: https://github.com/anza-xyz/sbpf/blob/2c91f24c7bc717547db62961f53bab17dc467bf2/src/memory_region.rs#L110
