use super::*;
use anyhow::{Context, Result};
use chrono::{DateTime, TimeZone, Utc};
use git2::{DiffFindOptions, DiffFormat, DiffOptions, Oid, Repository, Sort};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use regex::RegexSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::{debug, info, warn};

pub struct GitAnalyzer {
    repo: Repository,
    path: PathBuf,
}

const MAX_COMMITS_FOR_FULL_ANALYSIS: usize = 20000;
const MAX_FILES_PER_COMMIT: usize = 20;
const MAX_DIFF_BYTES: usize = 256 * 1024;

/// Minimum commits handed to one worker. Walking a contiguous run of history
/// keeps libgit2's pack windows and delta-base cache warm; splitting per commit
/// thrashes both and measured ~6x slower than chunking on this workload.
const MIN_COMMITS_PER_CHUNK: usize = 64;

/// Non-source paths kept out of the scanned diff: build output, vendored code,
/// lockfiles, translations. These mirror the git pathspecs this code used to
/// pass to `git show`, including git's globbing rule that `*` also matches `/`
/// for a non-`:(glob)` pathspec - so `*.lock` matches at any depth while
/// `vendor/*` only matches at the repository root.
const DIFF_EXCLUDES: &[&str] = &[
    "dist/*",
    "*/dist/*",
    "*.map",
    "*.license",
    "*.min.js",
    "*.min.css",
    "*/l10n/*",
    "3rdparty/*",
    "vendor/*",
    "node_modules/*",
    "composer.lock",
    "package-lock.json",
    "*.lock",
];

fn diff_excludes() -> &'static RegexSet {
    static SET: OnceLock<RegexSet> = OnceLock::new();
    SET.get_or_init(|| {
        let patterns: Vec<String> = DIFF_EXCLUDES
            .iter()
            .map(|glob| {
                let mut re = String::from("^");
                for ch in glob.chars() {
                    if ch == '*' {
                        re.push_str(".*");
                    } else {
                        re.push_str(&regex::escape(&ch.to_string()));
                    }
                }
                re.push('$');
                re
            })
            .collect();
        RegexSet::new(patterns).expect("static exclude globs must compile")
    })
}

fn is_excluded(path: &str) -> bool {
    diff_excludes().is_match(path)
}

/// What one commit contributes, extracted in-process from libgit2.
#[derive(Default)]
struct CommitDiff {
    files: Vec<String>,
    text: String,
    insertions: usize,
    deletions: usize,
}

impl GitAnalyzer {
    pub fn new(path: &Path) -> Result<Self> {
        let repo = Repository::open(path).with_context(|| {
            format!(
                "Failed to open repository at {}\n Is it really a git repo?",
                path.display()
            )
        })?;

        info!("Opened Git repository at {}", path.display());

        Ok(Self {
            repo,
            path: path.to_path_buf(),
        })
    }

    pub async fn analyze(&self) -> Result<RepositoryStats> {
        let mut stats = RepositoryStats {
            path: self.path.display().to_string(),
            total_commits: 0,
            total_files: 0,
            total_authors: 0,
            first_commit: Utc::now(),
            last_commit: Utc.timestamp_opt(0, 0).single().unwrap(),
            branches: Vec::new(),
            commit_history: Vec::new(),
            file_history: HashMap::new(),
            author_stats: HashMap::new(),
            single_author_files: Vec::new(),
            stale_files: Vec::new(),
            high_churn_files: Vec::new(),
            remote_url: None,
            repository_type: RepositoryType::Local,
            test_analysis: TestAnalysis {
                total_test_files: 0,
                test_directories: Vec::new(),
                test_frameworks: HashSet::new(),
                has_regression_tests: false,
                test_patterns_found: Vec::new(),
                test_coverage_indicators: Vec::new(),
            },
        };

        self.warn_on_incomplete_clone();
        self.analyze_branches(&mut stats)?;
        self.analyze_commits(&mut stats).await?;
        self.calculate_derived_stats(&mut stats)?;
        stats.remote_url = self.detect_remote_url();
        stats.repository_type = self.detect_repository_type(&stats.remote_url);

        info!(
            "Analysis complete: {} commits, {} files, {} authors",
            stats.total_commits, stats.total_files, stats.total_authors
        );

        Ok(stats)
    }

    fn analyze_branches(&self, stats: &mut RepositoryStats) -> Result<()> {
        let branches = self.repo.branches(Some(BranchType::Local))?;

        for branch in branches {
            let (branch, _) = branch?;
            if let Some(name) = branch.name()? {
                stats.branches.push(name.to_string());
            }
        }

        debug!("Found {} branches", stats.branches.len());
        Ok(())
    }

    async fn analyze_commits(&self, stats: &mut RepositoryStats) -> Result<()> {
        let mut revwalk = self.repo.revwalk()?;

        if let Ok(head) = self.repo.head() {
            if let Some(target) = head.target() {
                revwalk.push(target)?;
                info!(
                    "Analyzing commits from current branch: {}",
                    head.shorthand().unwrap_or("HEAD")
                );
            }
        } else {
            revwalk.push_head()?;
            info!("Analyzing commits from HEAD");
        }

        revwalk.set_sorting(Sort::TIME)?;

        let mut commit_oids = Vec::new();
        for oid in revwalk {
            commit_oids.push(oid?);
        }

        info!("Found {} commits to analyze", commit_oids.len());

        let commit_oids = if commit_oids.len() > MAX_COMMITS_FOR_FULL_ANALYSIS {
            info!(
                "Large repository detected, sampling {} most recent commits for performance",
                MAX_COMMITS_FOR_FULL_ANALYSIS
            );
            commit_oids
                .into_iter()
                .take(MAX_COMMITS_FOR_FULL_ANALYSIS)
                .collect()
        } else {
            commit_oids
        };

        if commit_oids.is_empty() {
            return Ok(());
        }

        let commit_infos = if Self::pack_exceeds_available_memory(&self.path) {
            info!(
                "Repository pack exceeds available memory; using the sequential \
                 native-git strategy instead of the chunked-parallel libgit2 walk \
                 (see `pack_exceeds_available_memory` for why)."
            );
            Self::analyze_commits_bulk_native(&self.path, commit_oids.len()).await?
        } else {
            self.commit_infos_via_parallel_libgit2(commit_oids)
        };

        // A commit whose files we can name but whose contents we cannot read is
        // one whose blobs are absent locally. We never fetch them, so say how
        // much of the diff scanning is running blind rather than quietly
        // reporting zero findings.
        let blind = commit_infos
            .iter()
            .filter(|c| c.diff.is_empty() && !c.files_changed.is_empty())
            .count();
        if blind * 10 > commit_infos.len() {
            warn!(
                "{}/{} commits ({}%) have no readable diff because their blobs are \
                 not present locally; diff-based signatures are incomplete for those. \
                 Objects are never fetched from a remote - see the partial clone note above.",
                blind,
                commit_infos.len(),
                blind * 100 / commit_infos.len().max(1)
            );
        }

        // Apply updates sequentially (mutable stats require this)
        for commit_info in commit_infos {
            if commit_info.authored_date < stats.first_commit {
                stats.first_commit = commit_info.authored_date;
            }
            if commit_info.authored_date > stats.last_commit {
                stats.last_commit = commit_info.authored_date;
            }

            self.update_author_stats(stats, &commit_info);
            self.update_file_history(stats, &commit_info);

            stats.commit_history.push(commit_info);
            stats.total_commits += 1;
        }

        Ok(())
    }

    /// Read every commit through libgit2 in this process. There are no `git`
    /// subprocesses: the old code spawned two per commit, which on a 20k
    /// commit repository meant 40k fork/exec calls, and on macOS each one
    /// also paid for the /usr/bin/git xcselect shim re-exec.
    ///
    /// Work is split into contiguous chunks, one libgit2 handle per chunk,
    /// because locality dominates here - see `MIN_COMMITS_PER_CHUNK`. This is
    /// the fast path when the repository's pack fits in available memory; see
    /// `pack_exceeds_available_memory` for when `analyze_commits` instead uses
    /// `analyze_commits_bulk_native`.
    fn commit_infos_via_parallel_libgit2(&self, commit_oids: Vec<Oid>) -> Vec<CommitInfo> {
        let pb = ProgressBar::new(commit_oids.len() as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} commits ({eta})"
            )
            .unwrap()
            .progress_chars("#>-")
        );

        let threads = rayon::current_num_threads().max(1);
        let chunk_size = commit_oids
            .len()
            .div_ceil(threads)
            .max(MIN_COMMITS_PER_CHUNK);
        let repo_path = self.path.clone();

        let commit_infos: Vec<CommitInfo> = commit_oids
            .par_chunks(chunk_size)
            .map(|chunk| {
                // One handle per chunk; it never crosses a thread boundary.
                let repo = match Repository::open(&repo_path) {
                    Ok(repo) => repo,
                    Err(e) => {
                        debug!("Could not open repository on worker: {}", e);
                        return Vec::new();
                    }
                };

                let mut out = Vec::with_capacity(chunk.len());
                for &oid in chunk {
                    if let Some(info) = Self::build_commit_info(&repo, oid) {
                        out.push(info);
                    }
                    pb.inc(1);
                }
                out
            })
            .flatten()
            .collect();

        pb.finish_with_message("Commit analysis complete");
        commit_infos
    }

    /// Build one `CommitInfo` from libgit2 alone.
    ///
    /// Nothing here can reach the network: libgit2 has no promisor/partial-clone
    /// support, so an object that is missing locally surfaces as an error we
    /// degrade on, never as a lazy fetch. Returns `None` only when the commit
    /// itself cannot be read.
    fn build_commit_info(repo: &Repository, oid: Oid) -> Option<CommitInfo> {
        let commit = match repo.find_commit(oid) {
            Ok(commit) => commit,
            Err(e) => {
                debug!("Skipping unreadable commit {}: {}", oid, e);
                return None;
            }
        };

        let to_utc = |t: git2::Time| {
            Utc.timestamp_opt(t.seconds(), 0)
                .single()
                .unwrap_or_else(Utc::now)
        };

        let author = commit.author();
        let committer = commit.committer();
        let authored_date = to_utc(author.when());
        let committed_date = to_utc(committer.when());

        let diff = Self::commit_diff(repo, &commit);

        Some(CommitInfo {
            id: commit.id().to_string(),
            message: commit.message().unwrap_or("").to_string(),
            author: String::from_utf8_lossy(author.name_bytes()).to_string(),
            author_email: String::from_utf8_lossy(author.email_bytes()).to_string(),
            committer: String::from_utf8_lossy(committer.name_bytes()).to_string(),
            committer_email: String::from_utf8_lossy(committer.email_bytes()).to_string(),
            authored_date,
            committed_date,
            files_changed: diff.files,
            insertions: diff.insertions,
            deletions: diff.deletions,
            branch: None,
            diff: diff.text,
        })
    }

    /// Diff a commit against its first parent (against the empty tree for a root
    /// commit), yielding the changed paths plus the added/removed lines that the
    /// signature patterns scan. Size-capped, and never fails: any unreadable
    /// object degrades to an empty result.
    fn commit_diff(repo: &Repository, commit: &git2::Commit<'_>) -> CommitDiff {
        let mut result = CommitDiff::default();

        let tree = match commit.tree() {
            Ok(tree) => tree,
            Err(e) => {
                debug!("No tree for commit {}: {}", commit.id(), e);
                return result;
            }
        };
        // A root commit has no parent, so it diffs against the empty tree and
        // every file reads as added. The subprocess version had a `git show
        // --name-only` fallback meant for this, but it was unreachable: it only
        // ran after a *successful* `diff-tree`, and `diff-tree <root>~1` exits
        // non-zero, so initial commits silently came back with no files at all.
        let parent_tree = commit.parent(0).and_then(|p| p.tree()).ok();

        // Deliberately leaving `include_typechange` off: with it enabled libgit2
        // collapses e.g. a symlink-to-file change into one Typechange delta that
        // renders no patch text at all, silently dropping the diff. The default
        // splits it into delete + add, which is what `git show` prints. Submodule
        // changes are likewise left visible, matching `git diff-tree`.
        let mut opts = DiffOptions::new();
        opts.context_lines(0);

        let mut diff =
            match repo.diff_tree_to_tree(parent_tree.as_ref(), Some(&tree), Some(&mut opts)) {
                Ok(diff) => diff,
                Err(e) => {
                    debug!("Could not diff commit {}: {}", commit.id(), e);
                    return result;
                }
            };

        // A typechange arrives as a delete/add pair over the same path, so
        // de-duplicate to keep `git diff-tree --name-only`'s one-line-per-file
        // shape while preserving first-seen order.
        let mut seen = HashSet::new();
        for delta in diff.deltas() {
            let path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_string_lossy().to_string());
            if let Some(path) = path {
                if !seen.insert(path.clone()) {
                    continue;
                }
                result.files.push(path);
                if result.files.len() >= MAX_FILES_PER_COMMIT {
                    break;
                }
            }
        }

        // The path list above intentionally came from the rename-agnostic delta
        // list, matching `git diff-tree --name-only -r`, which is plumbing and
        // reports a rename as both the old and the new path.
        //
        // The patch text, by contrast, has to match `git show`, where rename
        // detection is on by default: a pure rename collapses to a header with
        // no content lines. Without this, libgit2 reports a move as delete+add
        // and hands the scanner an entire relocated file as "added" lines -
        // which reads as a wave of new findings that are purely false positives.
        //
        // 50 is git's own default similarity threshold. libgit2 and git do not
        // score renames identically, so individual commits can still differ by
        // a few lines either way; 50 tracked git most closely across a 4367
        // commit corpus and reproduced its finding set exactly.
        let mut find = DiffFindOptions::new();
        find.renames(true).rename_threshold(50);
        if let Err(e) = diff.find_similar(Some(&mut find)) {
            debug!("Rename detection failed for {}: {}", commit.id(), e);
        }

        // Keep only added/removed lines. Line origins from libgit2 already
        // separate content from the +++/--- file headers and @@ hunk headers,
        // so no textual filtering is needed.
        let mut text = String::new();
        let mut truncated = false;
        let mut cached: Option<(String, bool)> = None;

        let printed = diff.print(DiffFormat::Patch, |delta, _hunk, line| {
            let origin = line.origin();
            if origin != '+' && origin != '-' {
                return true;
            }

            if origin == '+' {
                result.insertions += 1;
            } else {
                result.deletions += 1;
            }

            if truncated {
                return true;
            }

            // Deltas arrive grouped by file, so remember the last verdict rather
            // than re-matching the exclude set on every line.
            let path = delta
                .new_file()
                .path()
                .or_else(|| delta.old_file().path())
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let excluded = match &cached {
                Some((cached_path, verdict)) if *cached_path == path => *verdict,
                _ => {
                    let verdict = is_excluded(&path);
                    cached = Some((path, verdict));
                    verdict
                }
            };
            if excluded {
                return true;
            }

            text.push(origin);
            let content = String::from_utf8_lossy(line.content());
            text.push_str(&content);
            if !content.ends_with('\n') {
                text.push('\n');
            }

            if text.len() >= MAX_DIFF_BYTES {
                text.push_str("\n[diff truncated]\n");
                truncated = true;
            }
            true
        });

        if let Err(e) = printed {
            debug!("Partial diff for commit {}: {}", commit.id(), e);
        }

        result.text = text;
        result
    }

    /// Whether the repository's on-disk pack data is bigger than the memory
    /// available to cache it. Below this line, libgit2's chunked-parallel walk
    /// (see `MIN_COMMITS_PER_CHUNK`) is the faster strategy: object lookups hit
    /// a warm page cache and threads add real throughput. Above it, chunking
    /// splits history into far-apart slices that each need their own working
    /// set, so N threads compete for cache instead of sharing it, and a single
    /// sequential `git log` walk - which only ever needs a sliding window of
    /// history, since consecutive commits share most of their tree - wins by a
    /// wide margin (measured ~70-170x on a 65 GB / ~11 GB available repo).
    fn pack_exceeds_available_memory(repo_path: &Path) -> bool {
        let pack_bytes = Self::total_pack_bytes(repo_path);
        let available_bytes = Self::available_memory_bytes();
        pack_bytes > available_bytes
    }

    /// Sum of `*.pack` files under the repository's object store. Zero (and so
    /// "small enough") if the directory cannot be read, which keeps the
    /// existing libgit2 path as the safe default when this check is
    /// inconclusive rather than silently switching strategy.
    fn total_pack_bytes(repo_path: &Path) -> u64 {
        let pack_dir = repo_path.join(".git/objects/pack");
        let pack_dir = if pack_dir.is_dir() {
            pack_dir
        } else {
            repo_path.join("objects/pack") // bare repository layout
        };

        let Ok(entries) = std::fs::read_dir(&pack_dir) else {
            return 0;
        };

        entries
            .flatten()
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "pack"))
            .filter_map(|entry| entry.metadata().ok())
            .map(|meta| meta.len())
            .sum()
    }

    /// `MemAvailable` from `/proc/meminfo`, in bytes. `u64::MAX` (so "assume
    /// plenty of memory", i.e. never switch strategy) when unavailable, which
    /// is the case on any non-Linux platform this runs on.
    fn available_memory_bytes() -> u64 {
        let Ok(contents) = std::fs::read_to_string("/proc/meminfo") else {
            return u64::MAX;
        };
        Self::parse_mem_available_kb(&contents)
            .map(|kb| kb.saturating_mul(1024))
            .unwrap_or(u64::MAX)
    }

    fn parse_mem_available_kb(meminfo: &str) -> Option<u64> {
        meminfo
            .lines()
            .find_map(|line| line.strip_prefix("MemAvailable:"))
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|kb| kb.parse().ok())
    }

    /// Single-process, sequential alternative to the chunked-parallel walk for
    /// when the repository's data does not fit in memory (see
    /// `pack_exceeds_available_memory`). One `git log` invocation streams the
    /// whole requested range in commit order, which is the access pattern
    /// `git bisect` and friends already rely on to keep pack windows warm, then
    /// this parses that stream into the same `CommitInfo` records the
    /// chunked-parallel path produces (matching its rename-detection threshold
    /// and per-file diff-exclude behavior; see `commit_diff` for the
    /// authoritative semantics this mirrors).
    async fn analyze_commits_bulk_native(
        repo_path: &Path,
        max_commits: usize,
    ) -> Result<Vec<CommitInfo>> {
        const RECORD_SEP: char = '\u{1}';
        const FIELD_SEP: char = '\u{2}';
        const BODY_END: char = '\u{3}';

        let format = format!(
            "{RECORD_SEP}%H{FIELD_SEP}%an{FIELD_SEP}%ae{FIELD_SEP}%cn{FIELD_SEP}%ce{FIELD_SEP}%at{FIELD_SEP}%ct{FIELD_SEP}%B{BODY_END}"
        );

        let output = tokio::process::Command::new("git")
            .arg("-C")
            .arg(repo_path)
            .args([
                "log",
                "--no-color",
                "--patch",
                "--unified=0",
                "--find-renames=50%",
                "-n",
            ])
            .arg(max_commits.to_string())
            .arg(format!("--format={format}"))
            .arg("HEAD")
            .kill_on_drop(true)
            .output()
            .await
            .context("failed to spawn `git log` for the bulk sequential scan")?;

        if !output.status.success() {
            anyhow::bail!(
                "`git log` exited with {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .split(RECORD_SEP)
            .filter(|record| !record.is_empty())
            .filter_map(Self::parse_bulk_record)
            .collect())
    }

    /// Parses one `RECORD_SEP`-delimited chunk of the bulk `git log` output
    /// (header fields up to `BODY_END`, then that commit's patch) into a
    /// `CommitInfo`. Returns `None` for a record too malformed to have a
    /// commit id, mirroring `build_commit_info`'s "skip unreadable" behavior.
    fn parse_bulk_record(record: &str) -> Option<CommitInfo> {
        const FIELD_SEP: char = '\u{2}';
        const BODY_END: char = '\u{3}';

        let (header, patch) = record.split_once(BODY_END).unwrap_or((record, ""));
        let mut fields = header.splitn(8, FIELD_SEP);

        let id = fields.next()?.to_string();
        if id.is_empty() {
            return None;
        }
        let author = fields.next().unwrap_or_default().to_string();
        let author_email = fields.next().unwrap_or_default().to_string();
        let committer = fields.next().unwrap_or_default().to_string();
        let committer_email = fields.next().unwrap_or_default().to_string();
        let authored_date = Self::parse_unix_timestamp(fields.next())?;
        let committed_date = Self::parse_unix_timestamp(fields.next())?;
        let message = fields.next().unwrap_or_default().trim_end().to_string();

        let diff = Self::parse_bulk_patch(patch);

        Some(CommitInfo {
            id,
            message,
            author,
            author_email,
            committer,
            committer_email,
            authored_date,
            committed_date,
            files_changed: diff.files,
            insertions: diff.insertions,
            deletions: diff.deletions,
            branch: None,
            diff: diff.text,
        })
    }

    fn parse_unix_timestamp(field: Option<&str>) -> Option<DateTime<Utc>> {
        let seconds: i64 = field?.trim().parse().ok()?;
        Utc.timestamp_opt(seconds, 0).single()
    }

    /// Extracts the same `CommitDiff` shape `commit_diff` computes from
    /// libgit2, from one commit's unified-diff text instead. Insertions and
    /// deletions count every changed line; the accumulated `text` (what the
    /// signature patterns scan) drops lines from excluded paths, checked once
    /// per file and cached for that file's remaining lines, exactly like
    /// `commit_diff`'s per-line callback.
    fn parse_bulk_patch(patch: &str) -> CommitDiff {
        let mut result = CommitDiff::default();
        let mut current_excluded = false;
        let mut truncated = false;

        for line in patch.lines() {
            if let Some(path) = Self::diff_header_new_path(line) {
                if result.files.len() < MAX_FILES_PER_COMMIT {
                    result.files.push(path.clone());
                }
                current_excluded = is_excluded(&path);
                continue;
            }

            let is_addition = line.starts_with('+') && !line.starts_with("+++");
            let is_deletion = line.starts_with('-') && !line.starts_with("---");
            if !is_addition && !is_deletion {
                continue;
            }

            if is_addition {
                result.insertions += 1;
            } else {
                result.deletions += 1;
            }

            if current_excluded || truncated {
                continue;
            }

            result.text.push_str(line);
            result.text.push('\n');
            if result.text.len() >= MAX_DIFF_BYTES {
                result.text.push_str("\n[diff truncated]\n");
                truncated = true;
            }
        }

        result
    }

    /// Parses a unified-diff file header line (`diff --git a/<old> b/<new>`)
    /// into the path this file's changed lines should be attributed to,
    /// preferring the new-side path the way `commit_diff` prefers
    /// `delta.new_file()`. Returns `None` for any other line.
    fn diff_header_new_path(line: &str) -> Option<String> {
        let rest = line.strip_prefix("diff --git a/")?;
        let (_old, new) = rest.split_once(" b/")?;
        Some(new.to_string())
    }

    /// Report clone shapes that leave objects missing locally. commitraider
    /// analyzes only what the repository already has and never fetches, so a
    /// partial or shallow clone silently narrows diff coverage unless we say so.
    fn warn_on_incomplete_clone(&self) {
        if self.repo.is_shallow() {
            warn!(
                "Shallow clone: history is truncated, so only the commits present \
                 locally are analyzed. Run `git fetch --unshallow` for full history."
            );
        }

        let config = match self.repo.config() {
            Ok(config) => config,
            Err(_) => return,
        };

        let mut promisors = Vec::new();
        if let Ok(remotes) = self.repo.remotes() {
            for name in remotes.iter().flatten() {
                if config
                    .get_bool(&format!("remote.{}.promisor", name))
                    .unwrap_or(false)
                {
                    let filter = config
                        .get_string(&format!("remote.{}.partialclonefilter", name))
                        .unwrap_or_default();
                    promisors.push(if filter.is_empty() {
                        name.to_string()
                    } else {
                        format!("{} (filter: {})", name, filter)
                    });
                }
            }
        }

        if !promisors.is_empty() {
            warn!(
                "Partial clone detected via promisor remote: {}. Missing object \
                 contents are NOT fetched - commitraider analyzes only what is \
                 already present, so diff-based signatures may be incomplete. For \
                 full coverage: git config --unset remote.<name>.partialclonefilter \
                 && git config --unset remote.<name>.promisor && git fetch --refetch",
                promisors.join(", ")
            );
        }
    }

    fn update_author_stats(&self, stats: &mut RepositoryStats, commit: &CommitInfo) {
        let author_key = format!("{}:{}", commit.author, commit.author_email);

        let author_stats = stats.author_stats.entry(author_key).or_insert(AuthorStats {
            name: commit.author.clone(),
            email: commit.author_email.clone(),
            commits: 0,
            files_touched: HashSet::new(),
            first_commit: commit.authored_date,
            last_commit: commit.authored_date,
            lines_added: 0,
            lines_removed: 0,
        });

        author_stats.commits += 1;
        author_stats.lines_added += commit.insertions;
        author_stats.lines_removed += commit.deletions;

        if commit.authored_date < author_stats.first_commit {
            author_stats.first_commit = commit.authored_date;
        }
        if commit.authored_date > author_stats.last_commit {
            author_stats.last_commit = commit.authored_date;
        }

        for file in &commit.files_changed {
            author_stats.files_touched.insert(file.clone());
        }
    }

    fn update_file_history(&self, stats: &mut RepositoryStats, commit: &CommitInfo) {
        for file_path in &commit.files_changed {
            let file_history = stats
                .file_history
                .entry(file_path.clone())
                .or_insert(FileHistory {
                    path: file_path.clone(),
                    commits: Vec::new(),
                    authors: HashSet::new(),
                    first_commit: commit.authored_date,
                    last_commit: commit.authored_date,
                    total_changes: 0,
                });

            file_history.commits.push(commit.id.clone());
            file_history.authors.insert(commit.author.clone());
            file_history.total_changes += 1;

            if commit.authored_date < file_history.first_commit {
                file_history.first_commit = commit.authored_date;
            }
            if commit.authored_date > file_history.last_commit {
                file_history.last_commit = commit.authored_date;
            }
        }
    }

    fn calculate_derived_stats(&self, stats: &mut RepositoryStats) -> Result<()> {
        stats.total_authors = stats.author_stats.len();
        stats.total_files = stats.file_history.len();

        // Find single-author files
        for (path, history) in &stats.file_history {
            if history.authors.len() == 1 {
                stats.single_author_files.push(path.clone());
            }
        }

        // Find stale files (no commits in last year)
        let one_year_ago = Utc::now() - chrono::Duration::days(365);
        for (path, history) in &stats.file_history {
            if history.last_commit < one_year_ago {
                stats.stale_files.push(path.clone());
            }
        }

        // Find high-churn files (top 10% by changes)
        let mut files_by_churn: Vec<_> = stats.file_history.iter().collect();
        files_by_churn.sort_by(|a, b| b.1.total_changes.cmp(&a.1.total_changes));

        let high_churn_threshold = files_by_churn.len() / 10; // Top 10%
        for (path, _) in files_by_churn.iter().take(high_churn_threshold.max(1)) {
            stats.high_churn_files.push(path.to_string());
        }

        info!(
            "Derived stats: {} single-author files, {} stale files, {} high-churn files",
            stats.single_author_files.len(),
            stats.stale_files.len(),
            stats.high_churn_files.len()
        );

        Ok(())
    }

    fn detect_remote_url(&self) -> Option<String> {
        if let Ok(remote) = self.repo.find_remote("origin") {
            if let Some(url) = remote.url() {
                return Some(url.to_string());
            }
        }

        if let Ok(remotes) = self.repo.remotes() {
            for i in 0..remotes.len() {
                if let Some(remote_name) = remotes.get(i) {
                    if let Ok(remote) = self.repo.find_remote(remote_name) {
                        if let Some(url) = remote.url() {
                            return Some(url.to_string());
                        }
                    }
                }
            }
        }

        None
    }

    fn detect_repository_type(&self, remote_url: &Option<String>) -> RepositoryType {
        if let Some(url) = remote_url {
            let url_lower = url.to_lowercase();
            if url_lower.contains("gitlab") {
                RepositoryType::GitLab
            } else if url_lower.contains("github") {
                RepositoryType::GitHub
            } else if url_lower.contains("bitbucket") {
                RepositoryType::Bitbucket
            } else {
                RepositoryType::Other
            }
        } else {
            RepositoryType::Local
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mem_available_kb_reads_the_right_line() {
        let meminfo = "MemTotal:       32000000 kB\n\
                        MemFree:         1000000 kB\n\
                        MemAvailable:   11000000 kB\n\
                        Buffers:          200000 kB\n";
        assert_eq!(
            GitAnalyzer::parse_mem_available_kb(meminfo),
            Some(11_000_000)
        );
    }

    #[test]
    fn parse_mem_available_kb_missing_line_is_none() {
        let meminfo = "MemTotal:       32000000 kB\n";
        assert_eq!(GitAnalyzer::parse_mem_available_kb(meminfo), None);
    }

    #[test]
    fn total_pack_bytes_sums_pack_files_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pack_dir = dir.path().join(".git/objects/pack");
        std::fs::create_dir_all(&pack_dir).expect("mkdir");
        std::fs::write(pack_dir.join("pack-a.pack"), vec![0u8; 100]).expect("write");
        std::fs::write(pack_dir.join("pack-a.idx"), vec![0u8; 999]).expect("write");
        std::fs::write(pack_dir.join("pack-b.pack"), vec![0u8; 50]).expect("write");

        assert_eq!(GitAnalyzer::total_pack_bytes(dir.path()), 150);
    }

    #[test]
    fn total_pack_bytes_missing_dir_is_zero() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(GitAnalyzer::total_pack_bytes(dir.path()), 0);
    }

    #[test]
    fn diff_header_new_path_extracts_the_new_side() {
        assert_eq!(
            GitAnalyzer::diff_header_new_path("diff --git a/old/path.rs b/new/path.rs"),
            Some("new/path.rs".to_string())
        );
        assert_eq!(GitAnalyzer::diff_header_new_path("+some content"), None);
    }

    #[test]
    fn parse_bulk_patch_counts_all_lines_but_excludes_text_for_excluded_paths() {
        let patch = "diff --git a/src/lib.rs b/src/lib.rs\n\
                      index 000..111 100644\n\
                      --- a/src/lib.rs\n\
                      +++ b/src/lib.rs\n\
                      @@ -1,0 +1,2 @@\n\
                      +fn added() {}\n\
                      +fn also_added() {}\n\
                      diff --git a/package-lock.json b/package-lock.json\n\
                      index 222..333 100644\n\
                      --- a/package-lock.json\n\
                      +++ b/package-lock.json\n\
                      @@ -1,0 +1,1 @@\n\
                      +\"excluded\": true\n";

        let diff = GitAnalyzer::parse_bulk_patch(patch);

        assert_eq!(diff.files, vec!["src/lib.rs", "package-lock.json"]);
        // All +/- lines count, including the excluded file's.
        assert_eq!(diff.insertions, 3);
        assert_eq!(diff.deletions, 0);
        // But only the non-excluded file's content reaches the scanned text.
        assert!(diff.text.contains("fn added()"));
        assert!(!diff.text.contains("excluded"));
    }

    #[test]
    fn parse_bulk_patch_pure_rename_has_no_content_lines() {
        let patch = "diff --git a/old_name.rs b/new_name.rs\n\
                      similarity index 100%\n\
                      rename from old_name.rs\n\
                      rename to new_name.rs\n";

        let diff = GitAnalyzer::parse_bulk_patch(patch);

        assert_eq!(diff.files, vec!["new_name.rs"]);
        assert_eq!(diff.insertions, 0);
        assert_eq!(diff.deletions, 0);
        assert!(diff.text.is_empty());
    }

    #[test]
    fn parse_bulk_record_extracts_header_fields_and_patch() {
        // No leading RECORD_SEP: `analyze_commits_bulk_native` splits the raw
        // `git log` output on it before calling `parse_bulk_record`, so a
        // record never actually contains one.
        let record = "abc123\u{2}Jane Doe\u{2}jane@example.com\u{2}\
                       Jane Doe\u{2}jane@example.com\u{2}1700000000\u{2}1700000100\u{2}\
                       Fix a bug\n\u{3}diff --git a/src/lib.rs b/src/lib.rs\n\
                       --- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,0 +1,1 @@\n+fixed()\n";

        let info = GitAnalyzer::parse_bulk_record(record).expect("should parse");

        assert_eq!(info.id, "abc123");
        assert_eq!(info.author, "Jane Doe");
        assert_eq!(info.author_email, "jane@example.com");
        assert_eq!(info.message, "Fix a bug");
        assert_eq!(info.authored_date.timestamp(), 1_700_000_000);
        assert_eq!(info.committed_date.timestamp(), 1_700_000_100);
        assert_eq!(info.files_changed, vec!["src/lib.rs"]);
        assert_eq!(info.insertions, 1);
        assert!(info.diff.contains("fixed()"));
    }

    #[test]
    fn parse_bulk_record_without_commit_id_is_none() {
        assert!(GitAnalyzer::parse_bulk_record("").is_none());
    }
}
