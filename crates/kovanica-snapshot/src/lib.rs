//! Read-only snapshot manifest inspection and non-destructive chunk verification reporting.
//!
//! All functions in this crate are strictly read-only with respect to snapshot
//! files and directories: they never create, modify, or delete any files on disk.

pub mod report;

pub use report::{
    inspect_snapshot_manifest, verify_snapshot_report, SnapshotChunkEntry, SnapshotManifest,
    SnapshotManifestSummary, SnapshotVerificationReport, DEFAULT_MANIFEST_FILENAMES,
    DIGEST_ALGORITHM_BLAKE3,
};
