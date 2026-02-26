//! SIMD-0460 stack frame gap impact analysis.
//!
//! SIMD-0460 ("Virtual Address Space Adjustments") removes stack frame gaps
//! globally, even for existing SBPFv0 programs. This module provides static
//! analysis passes that scan program binaries for memory accesses that would
//! change behavior after the gap removal.

use anyhow::{Context, Result};
use either::Either;
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use sbpf_common::opcode::{Opcode, LOAD_MEMORY_OPS, STORE_IMM_OPS, STORE_REG_OPS};
use sbpf_disassembler::program::Program;
use std::collections::HashMap;
use std::fmt;
use std::io::Write;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Gap-band classification
// ---------------------------------------------------------------------------

/// Gap band regions relative to r10 in the SBPFv0 stack layout.
///
/// With stack frame gaps enabled (SBPFv0), each call depth has a 4 KiB mapped
/// frame followed by a 4 KiB unmapped gap. r10 points to the top of the
/// current frame, so the layout around r10 at depth >= 1 is:
///
///   ┌──────────────────┐ r10 + 4096
///   │  unmapped gap    │ offsets [0, +4095]     ← PositiveGap
///   ├──────────────────┤ r10
///   │  mapped frame    │ offsets [-4096, -1]    ← valid
///   ├──────────────────┤ r10 - 4096
///   │  unmapped gap    │ offsets [-8192, -4097] ← NegativeGap
///   ├──────────────────┤ r10 - 8192
///   │  prev frame      │ ...
///   └──────────────────┘
///
/// After SIMD-0460, gaps are removed and frames are packed contiguously.
/// Accesses that currently fault on gap memory will silently hit adjacent
/// frames' data, which is the behavior change this scan detects.
enum GapBand {
    /// [0, +4095] — gap above the current frame.
    Positive,
    /// [-8192, -4097] — gap below the current frame (between frames).
    Negative,
}

impl fmt::Display for GapBand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GapBand::Positive => write!(f, "positive [0, +4095]"),
            GapBand::Negative => write!(f, "negative [-8192, -4097]"),
        }
    }
}

/// Check whether an i16 offset from r10 lands in a stack frame gap band.
fn classify_gap_offset(offset: i16) -> Option<GapBand> {
    if (0..=4095).contains(&offset) {
        Some(GapBand::Positive)
    } else if (-8192..=-4097).contains(&offset) {
        Some(GapBand::Negative)
    } else {
        None
    }
}

/// Return the base register number for a memory instruction, or `None` if
/// the instruction is not a memory operation.
///
/// For loads (ldx*), the base address register is `src`.
/// For stores (st*, stx*), the base address register is `dst`.
fn memory_base_reg_num(insn: &sbpf_common::instruction::Instruction) -> Option<u8> {
    if LOAD_MEMORY_OPS.contains(&insn.opcode) {
        insn.src.as_ref().map(|r| r.n)
    } else if STORE_IMM_OPS.contains(&insn.opcode) || STORE_REG_OPS.contains(&insn.opcode) {
        insn.dst.as_ref().map(|r| r.n)
    } else {
        None
    }
}

/// Human label for an SBPF version derived from ELF e_flags.
fn sbpf_version_label(e_flags: u32) -> &'static str {
    match e_flags {
        0 => "V0",
        1 => "V1",
        2 => "V2",
        3 => "V3",
        4 => "V4",
        _ => "unknown",
    }
}

/// Format a memory instruction for disassembly output.
fn format_memory_insn(insn: &sbpf_common::instruction::Instruction) -> String {
    let op = insn.opcode.to_string();
    let off_str = insn
        .off
        .as_ref()
        .map(|o| match o {
            Either::Right(v) => {
                if *v >= 0 {
                    format!("+{}", v)
                } else {
                    format!("{}", v)
                }
            }
            Either::Left(s) => s.clone(),
        })
        .unwrap_or_default();

    if LOAD_MEMORY_OPS.contains(&insn.opcode) {
        let dst = insn.dst.as_ref().map(|r| format!("r{}", r.n)).unwrap_or_default();
        let src = insn.src.as_ref().map(|r| format!("r{}", r.n)).unwrap_or_default();
        format!("{} {}, [{}{}]", op, dst, src, off_str)
    } else if STORE_REG_OPS.contains(&insn.opcode) {
        let dst = insn.dst.as_ref().map(|r| format!("r{}", r.n)).unwrap_or_default();
        let src = insn.src.as_ref().map(|r| format!("r{}", r.n)).unwrap_or_default();
        format!("{} [{}{}], {}", op, dst, off_str, src)
    } else if STORE_IMM_OPS.contains(&insn.opcode) {
        let dst = insn.dst.as_ref().map(|r| format!("r{}", r.n)).unwrap_or_default();
        let imm = insn
            .imm
            .as_ref()
            .map(|i| match i {
                Either::Right(n) => format!("{}", n.to_i64()),
                Either::Left(s) => s.clone(),
            })
            .unwrap_or_default();
        format!("{} [{}{}], {}", op, dst, off_str, imm)
    } else {
        op
    }
}

/// Scan all programs for memory instructions that access r10 at gap-band
/// offsets.
///
/// This is the Tier 1 detection pass for SIMD-0460 impact analysis. It uses
/// the lightweight disassembler path (`Program::from_bytes` + `to_ixs`) to
/// iterate every instruction without building a CFG.
///
/// For each memory load/store where the base register is r10, the i16 `off`
/// field is checked against the two gap bands:
///
///   - Positive gap: offsets [0, +4095]
///   - Negative gap: offsets [-8192, -4097]
///
/// Any hit means the instruction currently faults (gap is unmapped) but would
/// silently succeed after SIMD-0460 removes the gap, potentially reading or
/// writing adjacent frame data. Since static analysis cannot determine runtime
/// call depth, we flag conservatively — the negative gap technically only
/// exists at depth >= 1, but we flag it at all depths.
///
/// This pass does NOT catch derived pointers (e.g. `mov64 r1, r10; add64 r1,
/// off; stxdw [r1], r2`). That requires the Tier 2 intra-block propagation
/// pass (`stack-gaps trace`).
pub fn offsets_command(program_dir: String, disasm: bool, ids_out: Option<String>) -> Result<()> {
    println!("\nStack Frame Gap Analysis — Offset Scan");
    println!("{}", "=".repeat(60));

    if !Path::new(&program_dir).exists() {
        anyhow::bail!("Directory '{}' not found. Run sync first.", program_dir);
    }

    let entries = fs::read_dir(&program_dir)?;
    let so_files: Vec<_> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "so").unwrap_or(false))
        .collect();

    println!("Found {} .so files to analyze", so_files.len());
    println!("Scanning r10-based memory ops for gap-band offsets");
    println!();

    let pb = ProgressBar::new(so_files.len() as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("  [{bar:40.green/black}] {pos}/{len}")
            .unwrap()
            .progress_chars("█▓░"),
    );

    // Per-program results: (pubkey, e_flags, hits).
    // Each hit: (pc, offset, opcode_name, gap_band, disasm_text).
    let flagged: Mutex<Vec<(String, u32, Vec<(usize, i16, String, GapBand, String)>)>> =
        Mutex::new(Vec::new());
    let files_processed = AtomicUsize::new(0);
    let files_with_errors = AtomicUsize::new(0);
    let error_log = Mutex::new(Vec::<(String, String)>::new());
    let total_gap_hits = AtomicUsize::new(0);

    so_files.par_iter().for_each(|entry| {
        let path = entry.path();
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        let pubkey = path.file_stem().unwrap().to_string_lossy().to_string();

        let elf_data = match fs::read(&path) {
            Ok(data) => data,
            Err(e) => {
                files_with_errors.fetch_add(1, Ordering::Relaxed);
                error_log
                    .lock()
                    .unwrap()
                    .push((filename, format!("Read error: {}", e)));
                pb.inc(1);
                return;
            }
        };

        let program = match Program::from_bytes(&elf_data) {
            Ok(p) => p,
            Err(e) => {
                files_with_errors.fetch_add(1, Ordering::Relaxed);
                error_log
                    .lock()
                    .unwrap()
                    .push((filename, format!("Parse error: {}", e)));
                pb.inc(1);
                return;
            }
        };

        let e_flags = program.elf_header.e_flags;

        let instructions = match program.to_ixs() {
            Ok(i) => i,
            Err(e) => {
                files_with_errors.fetch_add(1, Ordering::Relaxed);
                error_log
                    .lock()
                    .unwrap()
                    .push((filename, format!("Disassembly error: {}", e)));
                pb.inc(1);
                return;
            }
        };

        let mut hits = Vec::new();
        let mut pc: usize = 0;

        for instruction in &instructions.0 {
            if let Some(base_reg) = memory_base_reg_num(instruction) {
                if base_reg == 10 {
                    if let Some(Either::Right(offset)) = &instruction.off {
                        if let Some(gap_band) = classify_gap_offset(*offset) {
                            let disasm_text = if disasm {
                                format_memory_insn(instruction)
                            } else {
                                String::new()
                            };
                            hits.push((
                                pc,
                                *offset,
                                instruction.opcode.to_string(),
                                gap_band,
                                disasm_text,
                            ));
                        }
                    }
                }
            }
            pc += if instruction.opcode == Opcode::Lddw { 2 } else { 1 };
        }

        if !hits.is_empty() {
            total_gap_hits.fetch_add(hits.len(), Ordering::Relaxed);
            flagged.lock().unwrap().push((pubkey, e_flags, hits));
        }

        files_processed.fetch_add(1, Ordering::Relaxed);
        pb.inc(1);
    });

    pb.finish_and_clear();

    let mut flagged = flagged.into_inner().unwrap();
    flagged.sort_by(|a, b| a.0.cmp(&b.0));
    let files_processed = files_processed.load(Ordering::Relaxed);
    let files_with_errors = files_with_errors.load(Ordering::Relaxed);
    let error_log = error_log.into_inner().unwrap();
    let total_gap_hits = total_gap_hits.load(Ordering::Relaxed);

    // Tally flagged programs by SBPF version.
    let mut version_counts: HashMap<u32, usize> = HashMap::new();
    for (_, version, _) in &flagged {
        *version_counts.entry(*version).or_insert(0) += 1;
    }

    // Tally flagged programs by gap band (positive, negative, or both).
    let mut pos_only = 0usize;
    let mut neg_only = 0usize;
    let mut both_bands = 0usize;
    for (_, _, hits) in &flagged {
        let has_pos = hits
            .iter()
            .any(|(_, _, _, g, _)| matches!(g, GapBand::Positive));
        let has_neg = hits
            .iter()
            .any(|(_, _, _, g, _)| matches!(g, GapBand::Negative));
        match (has_pos, has_neg) {
            (true, true) => both_bands += 1,
            (true, false) => pos_only += 1,
            (false, true) => neg_only += 1,
            (false, false) => {}
        }
    }

    println!("\n{}", "=".repeat(60));
    println!("RESULTS");
    println!("{}", "=".repeat(60));
    println!("Files processed:       {}", files_processed);
    println!("Files with errors:     {}", files_with_errors);
    println!("Programs flagged:      {}", flagged.len());
    println!("Total gap-band hits:   {}", total_gap_hits);
    println!();

    if !error_log.is_empty() {
        println!("Errors encountered:");
        println!("{}", "-".repeat(60));
        for (filename, error) in &error_log {
            println!("  {}: {}", filename, error);
        }
        println!();
    }

    if !version_counts.is_empty() {
        println!("Flagged programs by SBPF version:");
        println!("{}", "-".repeat(60));
        let mut versions: Vec<_> = version_counts.into_iter().collect();
        versions.sort_by_key(|(v, _)| *v);
        for (version, count) in &versions {
            println!("  {}: {} program(s)", sbpf_version_label(*version), count);
        }
        println!();
    }

    if !flagged.is_empty() {
        println!("Flagged programs by gap band:");
        println!("{}", "-".repeat(60));
        println!("  Positive only: {}", pos_only);
        println!("  Negative only: {}", neg_only);
        println!("  Both:          {}", both_bands);
        println!();
    }

    if !flagged.is_empty() {
        // Hits-per-program distribution.
        let hit_counts: Vec<i64> = flagged
            .iter()
            .map(|(_, _, hits)| hits.len() as i64)
            .collect();
        let min_hits = *hit_counts.iter().min().unwrap();
        let max_hits = *hit_counts.iter().max().unwrap();
        println!("Hits-per-program distribution:");
        println!("{}", "-".repeat(60));
        println!(
            "  [{min_hits} .. {max_hits}]  {}",
            super::sparkline::sparkline(&hit_counts, 20, None)
        );
        println!();

        // Offset distribution across gap bands.
        let all_offsets: Vec<i64> = flagged
            .iter()
            .flat_map(|(_, _, hits)| hits.iter().map(|(_, off, _, _, _)| *off as i64))
            .collect();
        let neg_offsets: Vec<i64> = all_offsets.iter().copied().filter(|o| *o < 0).collect();
        let pos_offsets: Vec<i64> = all_offsets.iter().copied().filter(|o| *o >= 0).collect();
        println!("Offset distribution:");
        println!("{}", "-".repeat(60));
        if !neg_offsets.is_empty() {
            let min_off = *neg_offsets.iter().min().unwrap();
            let max_off = *neg_offsets.iter().max().unwrap();
            println!(
                "  Negative [{min_off} .. {max_off}]  {}  ({} hits)",
                super::sparkline::sparkline(&neg_offsets, 20, None),
                neg_offsets.len()
            );
        }
        if !pos_offsets.is_empty() {
            let min_off = *pos_offsets.iter().min().unwrap();
            let max_off = *pos_offsets.iter().max().unwrap();
            println!(
                "  Positive [+{min_off} .. +{max_off}]  {}  ({} hits)",
                super::sparkline::sparkline(&pos_offsets, 20, None),
                pos_offsets.len()
            );
        }
        println!();
    }

    if flagged.is_empty() {
        println!("No programs with gap-band r10 offsets found.");
    } else {
        println!("Flagged programs:");
        println!("{}", "-".repeat(60));
        for (pubkey, version, hits) in &flagged {
            let pos_count = hits
                .iter()
                .filter(|(_, _, _, g, _)| matches!(g, GapBand::Positive))
                .count();
            let neg_count = hits
                .iter()
                .filter(|(_, _, _, g, _)| matches!(g, GapBand::Negative))
                .count();

            if disasm {
                println!(
                    "\n  {} (SBPF {}, {} hit(s): {} positive, {} negative):",
                    pubkey,
                    sbpf_version_label(*version),
                    hits.len(),
                    pos_count,
                    neg_count
                );
                for (pc, offset, _opcode, gap_band, disasm_text) in hits {
                    println!(
                        "    pc {:>5}: {}  (off={}, {})",
                        pc, disasm_text, offset, gap_band
                    );
                }
            } else {
                let pcs: Vec<usize> = hits.iter().map(|(pc, _, _, _, _)| *pc).collect();
                println!(
                    "  {} (SBPF {}, {} hit(s): {} pos/{} neg) pc {:?}",
                    pubkey,
                    sbpf_version_label(*version),
                    hits.len(),
                    pos_count,
                    neg_count,
                    pcs
                );
            }
        }
    }

    println!("{}", "=".repeat(60));

    if let Some(path) = ids_out {
        let mut f = fs::File::create(&path)
            .with_context(|| format!("Failed to create {}", path))?;
        for (pubkey, _, _) in &flagged {
            writeln!(f, "{}", pubkey)?;
        }
        println!("Wrote {} program IDs to {}", flagged.len(), path);
    }

    Ok(())
}

pub fn print_help() {
    println!("STACK-GAPS");
    println!("\nUSAGE:");
    println!("  program-sync stack-gaps <SUBCOMMAND> [OPTIONS]");
    println!("\nDESCRIPTION:");
    println!("  SIMD-0460 stack frame gap impact analysis. Scans programs for");
    println!("  memory accesses that target gap regions, which will change");
    println!("  behavior when stack frame gaps are removed.");
    println!("\nSUBCOMMANDS:");
    println!("  offsets     Scan r10-based memory ops for gap-band offsets (Tier 1)");
    println!("\nOPTIONS (offsets):");
    println!("  --dir <PATH>      Program directory (default: programs)");
    println!("  --disasm          Show disassembled instructions at each location");
    println!("  --help, -h        Show this help message");
    println!("\nGAP BANDS:");
    println!("  Positive: offsets [0, +4095] from r10 — gap above the current frame");
    println!("  Negative: offsets [-8192, -4097] from r10 — gap below the current frame");
    println!("\nEXAMPLES:");
    println!("  # Scan all programs for gap-band offsets");
    println!("  program-sync stack-gaps offsets");
    println!();
    println!("  # With disassembly output");
    println!("  program-sync stack-gaps offsets --disasm");
    println!();
    println!("  # Custom program directory");
    println!("  program-sync stack-gaps offsets --dir /path/to/programs");
    println!();
}
