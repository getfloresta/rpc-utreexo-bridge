## Bridge

This bridge maintains the Bitcoin UTXO accumulator and produces compact proofs for new blocks. It bootstraps from Bitcoin Core and then serves proofs to Utreexo-aware peers.

It contains three components:

- A parallel bootstrap builder for the historical flat forest, leaf map, and header index.
- A Pollard-backed steady-state prover that persists compact block proofs.
- A BIP324 P2PV2-only Bitcoin server that serves BIP183 block inclusion proofs and headers.

## Installation

### Requirements

- Rust 1.89.0 or later
- Linux x86-64
- A C++20 toolchain, CMake 3.22 or later, and Boost to compile `rust-bitcoinkernel`
- Because just keep things on RAM, you'll need a machine with at least 16GB of RAM.
- At least 500GB of free disk space, 1TB recommended.
- A trusted source of blocks to connect to. You can use Bitcoin Core.
- `rustreexo` 0.8.0 from crates.io, including the position-addressed Pollard cache APIs.
- `floresta-db` from <https://github.com/davidson-souza/floresta-db>, including the runtime
  batch, compaction, and online body-capacity APIs used by this bridge.

### From source

```bash
git clone https://github.com/getfloresta/rpc-utreexo-bridge
cd rpc-utreexo-bridge
cargo build --release
```

The final review was verified against local rustreexo revision
`e6748e572cff55366982652bca3f3cae3f1922cf` and floresta-db revision
`29397816fcd9fbef415820e4dbef18ab98104fe8`. The committed manifests use remote dependencies,
not sibling checkout paths. Remote builds require publication of rustreexo 0.8.0 and the
corresponding database changes; those publications were not available during this review.
The old local-dependency lockfiles are intentionally removed rather than presented as valid
remote resolutions. After publishing the dependencies, generate and commit both lockfiles:

```bash
cargo generate-lockfile
cargo generate-lockfile --manifest-path fuzz/Cargo.toml
cargo build --locked --release
```

CI and Docker generate a lockfile only when none exists, then build with `--locked`.

### Docker

We provide a Dockerfile that can be used to build a docker image. You can build it as follows:

```bash
docker build -t bridge .
```

or you can pull it from dockerhub:

```bash
docker pull dlsz/bridge
```

### Fuzzing

The fuzz package requires nightly Rust and `cargo-fuzz`:

```bash
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run journal_codec
cargo +nightly fuzz run pollard_behavior
```

`pollard_behavior` uses a cheap non-cryptographic `FastHash`; it does not invoke Bitcoin SHA-256
hashing in its update loop.

## Using

### Running the node

The bridge trusts Bitcoin Core for blocks and requires an explicit bootstrap or steady-state mode.
Generate a hints file and build the forest once, then run `--steady-state` as described below.
Starting the binary without either `--build-forest` or `--steady-state` is an error.

The bridge listens on port 8333 for BIP324 P2PV2 connections and serves Utreexo inclusion proofs with the BIP183 `getuproof`/`uproof` messages.

Inbound peers are capped at 64 connections. Handshakes expire after 10 seconds and are limited to 1 MiB/64 packets; established peers are disconnected for packets over 256 KiB, oversized request batches, or sustained rates above 100 packets per second.
Every minute, the node logs the connected-peer total and groups identified peers by their sanitized, self-reported software name, for example `Floresta=10 Satoshi=10`.

### Generating a hintsfile

`bridge-hints` is a standalone scanner that reads an unpruned Bitcoin Core datadir directly
through `rust-bitcoinkernel`; no RPC connection or credentials are used:

```bash
cargo build --release --bin bridge-hints
./target/release/bridge-hints \
    --network signet \
    --output /path/to/utxo.hints
```

If `--stop-height` is omitted, the existing Core active-chain tip is used. Standard Bitcoin Core
network paths are used (`$HOME/.bitcoin/signet` for Signet). Both tools open the already-synced
Core chainstate with `rust-bitcoinkernel::ChainstateManager` and read blocks through its active
chain entries; they do not run a second sync or reindex.

The scanner maintains the target-height UTXO set in memory and assigns per-block indices only to
outputs that are eligible for the Utreexo accumulator. OP_RETURN scripts, scripts larger than
10,000 bytes, same-block spends, and the first occurrences of the two historical BIP30-overwritten
outputs at heights 91,722 and 91,812 are excluded before the index is incremented. The output
starts with the bridge-owned `BRLFCT01` prefix, a little-endian stop height, and one little-endian
`u32` eligible-leaf count for every height from 1 through the stop height. The unchanged
`hintsfile` library payload follows immediately. The completed file is encoded to a temporary
file and atomically moved into place; raw library-generated hintsfiles without the prefix are not
accepted.

### Parallel flat-forest bootstrap

Linux builds can construct the historical forest directly in a preallocated, memory-mapped flat
file. The hintsfile stop height is the build target:

```bash
./target/release/bridge \
    --network signet \
    --build-forest /path/to/utxo.hints \
    --forest-file /path/to/forest.dat \
    --leaf-map-path /path/to/leaf-map \
    --header-file /path/to/headers.dat \
    --header-index-path /path/to/header-index
```

The leaf map defaults to `$DATA_DIR/leaf-map`. Headers default to `$DATA_DIR/headers.dat`, with
their hash index under `$DATA_DIR/header-index`. These output paths must not already exist.

`--forest-leaf-workers` and `--forest-chaser-workers` override the default half-CPU split.
`--forest-spin-iterations` controls how long chasers spin before sleeping on the publication
condition variable.
`--forest-leaf-capacity` raises the initial bottom-row capacity above the bootstrap leaf count; the
value must not be below the leaf count encoded through the hints stop height. Steady state grows
the mapped forest automatically when additions cross that capacity.
Leaf fetchers claim four-height chunks from a shared atomic allocator. Each acquisition returns
the next adjacent chunk, so a worker that finishes early immediately passes the others and takes
more work. No worker owns a fixed chain range.

Range acquisition and aggregate build timings are written at debug level to
`$DATA_DIR/debug.log`; terminal output contains lifecycle and progress information only.

The builder reads the deterministic per-block leaf counts from the bridge prefix and computes
every block's leaf offset without reading a block. It then reads each historical block exactly
once while the leaf workers populate the forest, leaf map, and header index.
Hints indices are interpreted over Utreexo-eligible outputs in block order; provably unspendable
outputs and outputs consumed in their creating block are excluded.

The same leaf workers write every 80-byte consensus header at
`height * size_of::<SerializedHeader>()` in the header flat file and insert its
`block_hash -> height` mapping into the fast database. Genesis occupies position zero.
Chasers own deterministic ranges, each covering at least two input pages except
where an entire upper row is smaller. A deleted child promotes its surviving sibling to the
parent; two deleted children mark the parent deleted, recursively promoting surviving subtrees
through roots. Independent ranges apply these rules concurrently with leaf publication.

The `floresta-db` leaf map uses an insert-only range writer, batching eligible
outputs once per block with `WriteOnlyWriter::put_batch`. Header mappings are
batched once per fetched range. The database groups keys by bucket before CAS
publication; fixed eight-byte positions and heights are stored inline. Mutable
bucket heads stay in memory during construction and are serialized during sync
or clean close.

Leaf-map keys are the first 16 bytes of SHA-256 over the 32-byte internal txid
followed by little-endian `vout`; values are little-endian `u64` bottom-row
positions. Header-index keys are the first 16 bytes of the internal block hash,
with inline `u64` heights; lookups verify the full hash against the stored header.
Only unspent leaves are indexed. A promoted leaf keeps its original bottom-row
value permanently—the parent chasers never update the map.

These indexes use `floresta-db` format v7. Existing variable-width-key leaf maps
and header indexes are incompatible: rebuild the bootstrap into fresh output
paths before running steady state. Do not mix an old index with a new forest.
On clean completion, runtime files are synced and closed directly without a
checkpoint snapshot. Crash recovery for interrupted builds remains unsupported.

The output has no header. A node at forest position `N` starts at
`N * size_of::<ForestNode>()`. Each 33-byte node contains a 32-byte hash and one flags byte:
bit 0 means initialized and bit 1 means spent. The file is sized for the complete positional space
at the required forest height; unused positions remain zero.

The builder uses `posix_fallocate`, `MADV_WILLNEED`, and `MADV_HUGEPAGE`. It also requests
`mlock2(MLOCK_ONFAULT)` so touched pages stay resident. Give the process an unlimited memlock
limit to make that request effective:

```bash
ulimit -l unlimited
./target/release/bridge --build-forest /path/to/utxo.hints
```

For a systemd service, set `LimitMEMLOCK=infinity`. Without that permission the builder logs a
warning and continues using the Linux page cache. `--forest-no-mlock` disables the request
explicitly. No sysctl changes are required; Linux will use otherwise-free RAM for the mapped file.
Avoid globally raising `vm.dirty_ratio`: it can starve the rest of the system and only postpones,
rather than removes, the final writeback.

### Sequential steady state

After bootstrap, continue from the hintsfile stop height with the same forest and leaf map:

```bash
./target/release/bridge \
    --network signet \
    --steady-state /path/to/utxo.hints \
    --forest-file /path/to/forest.dat \
    --leaf-map-path /path/to/leaf-map \
    --header-file /path/to/headers.dat \
    --header-index-path /path/to/header-index \
    --pollard-memory-mib 250
```
Bitcoin Core must be running with `txindex=1`. Each height uses `getblock` verbosity 3, which
returns the block transactions and every input's prevout in one RPC response. No additional
previous-block request is made for median-time-past: it is not used in leaf commitments or proofs.
Cache hits bypass prevout reconstruction. Creating block hashes are resolved exclusively from the in-memory cache
and persistent header index; steady-state proving never calls `getblockhash` for prevouts. A
missing height means the bootstrap header files do not match the forest. Providers without
verbosity-three support retain the per-transaction compatibility fallback. After resolving leaf
data, the prover verifies the batch proof, propagates deletions, appends eligible outputs, and
verifies the resulting roots against a `rustreexo` stump update. Outputs created and spent in the
same block never enter the forest.

Mutation planning uses an `AHashMap` overlay with position-sorted journal output. Independent
deletion parents are hashed by Rayon once a row has at least 128 parents; smaller rows stay local
to avoid scheduling overhead. Eligible addition leaf hashes use the same 128-item parallel
threshold. Addition positions no longer repeat leaf-map membership lookups already guaranteed by
the serialized block update.
The steady-state `Pollard` starts from the flat forest roots and keeps stable bottom positions for
remembered leaves. Cached spends resolve through that internal index without querying the
persistent leaf map or rereading the leaf hash. Cache misses resolve against pending outpoint
updates first, then query the unchanged portion of the leaf map in one ordered `batch_fetch`.
The Pollard reports uncached target and proof
positions, and only those hashes are read from the flat forest and ingested. The Pollard is
modified immediately and is the source of truth while journal records are pending.
`--pollard-memory-mib` sets its cache quota and defaults to 250 MiB. Cache eviction does not wait
for persistence: pending node and outpoint overlays keep subsequent cache misses current.
Bottom-to-proof position conversion sorts and detwins the live target frontier before fetching
sibling spentness. Sibling targets merge into one parent traversal without reading either sibling;
remaining sibling nodes are fetched once each in ascending physical-position order. The resulting
proof targets retain the original input order so they stay aligned with deletion hashes and leaf data.

Per-block cache metrics, foreground timings, and completed `background-persistence` timings are written at
debug level to `$DATA_DIR/debug.log`. Terminal logs report block height, hash, proof size, and
important lifecycle events without timing noise.

`steady-state-timings` retains the aggregate `positions` duration. The accompanying
`steady-state-position-timings` line splits it into:

- `cache`: leaf hashing, cached bottom-position lookup, and uncached-input collection.
- `leaf_map`: key preparation and the database batch fetch.
- `validation`: decoding index results, resolving overlay entries, and checking forest bounds.
  This does not read forest nodes to recheck spentness; Bitcoin Core already validated the spends.
- `resolution`: assembling bottom positions, including explicit recovery for missing or invalid entries.
- `traversal`: sorted, detwinned sibling fetching and conversion to canonical proof targets.

Each phase has a matching `*_majflt` field. On Linux these are `RUSAGE_THREAD` major-page-fault
deltas for the proving thread, excluding background workers: `Some(0)` means no major faults,
while `None` means the counter was unavailable. Faults indicate paging that required I/O, not
all storage waits; database syscalls and writeback stalls need not increment them. Measurements
are taken at phase boundaries, not per input. Phase times exclude counter-sampling overhead
and need not sum exactly to `positions`.

The persistent leaf map continues to hold stable bottom positions. Pending forest-node and
outpoint changes are overlaid in the foreground, including removals, so even a fully evicted
Pollard can prove blocks while the durable forest lags. Overlay entries carry their producing
height and are retired only when that height is acknowledged; retiring an earlier block cannot
discard a later update to the same node or outpoint. The runtime map is given 1 GiB of append
headroom; older bootstrap maps are extended in place before they are opened.

Journal application and rollback use per-block, key-sorted `batch_delete` and `put_batch`.
They remove the union of affected keys before reinsertion so replay remains idempotent even
though the database's append-only batch writer retains duplicate keys.

For each published window, the worker merges the blocks' position-sorted forest deltas and
writes each touched position exactly once, in ascending physical order. The last block's state
wins when positions overlap. A heap holds one cursor per nonempty block instead of copying
or sorting all node states into another window-sized buffer. Leaf-map changes and compaction
boundaries retain block order under the same exclusive lock. Per-block journal before/after
states remain unchanged for rollback and recovery of interrupted writes.

After applying each steady-state block with `height % 1_000 == 0`, the background
worker compacts leaf-map pages below half occupancy (16,384 live nodes per
1 MiB page), then syncs the forest and database before publishing completion.
The worker holds an exclusive forest lock only during mutation, relocation, and compaction;
foreground lookups cannot retain stale node offsets. During forest/database sync it holds a
shared lock, allowing proof planning and cache misses to run concurrently. Compaction failures
stop persistence rather than marking the height durable.
Header reads, bootstrap batches, synchronization, and steady-state index replacement/removal
share a separate storage read/write lock. The header index keeps 64 MiB of body append headroom
at startup. If a steady-state insertion exhausts that mapping, the persistence worker takes
exclusive storage access, fully closes and unmaps the database, adds another 64 MiB of headroom
beyond the allocator high-water mark, and reopens it before retrying the insertion once.
Existing header mappings are preserved without restarting or rebuilding; a growth event is logged.
Readers and synchronization wait through the remapping, and bootstrap writers borrow their
database handle only for each locked batch. A close, growth, or reopen failure is returned to
persistence and leaves the index explicitly unavailable rather than using a stale mapping.
This does not change allocator page sealing: synchronization can still leave partially used pages.

Online growth doubles the bottom-row capacity without restarting the bridge. An explicit sync
first publishes and applies any partial window, internal rows are relocated into the enlarged
positional layout, and the newly exposed bottom positions are cleared before proving continues.
A durable `forest.resize` sidecar records the relocation phase; startup resumes an interrupted
resize before opening the steady-state forest. Journal records retain their physical forest-row
count so replay and rollback translate old node positions into the current layout. Proof-index
entries separately retain the logical row count used by their targets, keeping proofs created
before and after a resize wire-compatible.

Post-hints proofs are appended to `$DATA_DIR/proofs` and indexed by block hash under
`$DATA_DIR/proof-index`. Records contain only targets, proof hashes, and compact leaf data—Bitcoin
blocks are fetched from Core and are not retained.

The prover appends complete page-aligned records to `$DATA_DIR/forest.journal` without syncing.
Each record contains the block identity, post-block `numleaves`, changed forest positions with
before/after hashes and flags, added/removed outpoints with stable bottom positions, the block
header, compact proof, and both physical and proof forest-row counts. Pending changes remain in the foreground
overlay; no corresponding forest, leaf-map, header, proof, or proof-index writes occur yet.

Every **100 new blocks**, the prover submits an immutable journal end offset to the persistence
worker. The worker flushes the journal, advances the checksummed publication marker in
`forest.journal.published`, then flushes that marker. Alternating marker slots protect against a
torn update. Later appends may reach disk during this operation, but are not included in the
captured publication boundary. Journal publication holds no producer metadata lock across sync.

Only after publication succeeds does the worker write proofs, headers, and proof-index entries,
apply merged forest writes and block-ordered leaf-map changes, sync those stores, and commit the final applied
height. Notifications and completions follow that applied-height commit, not journal publication.
There is at most one submitted window and one accumulating window: **200 pending blocks**.
The old 256 MiB pending-memory gate is removed because it could prevent reaching publication;
memory usage now depends on the contents of those bounded windows, separately from the Pollard
cache quota. Journal entries and proof payloads are shared rather than copied into each queue.

`persistence_enqueue` includes unsynced journal append and window-boundary backpressure.
`background-persistence` reports `publication` (journal flush, marker bump, marker flush),
`apply`, `state_flush`, `proof_store`, `header_store`, `proof_index_write`, and `height_commit`.
Its `first_height`, `height` (last height), and `blocks` identify the window; durations are window
totals. Completing a prover range publishes its partial window and waits for application before
returning, so catching up to Core's tip makes every generated proof available to P2P. During
normal operation, even a single newly mined block is published at the end of its range.

Explicit sync and graceful shutdown also publish partial windows and wait for application.
Capacity growth and position repair explicitly sync before their ordered worker operations. Reorgs drain
already submitted work, discard the entire unpublished tail, then roll back published orphan
blocks; any still-active discarded prefix is reproved. Ordinary drop or an error never submits a
partial window. All flushes and durable-store writes remain on background workers; the prover
only writes unsynced journal records. Buffered writes can still encounter kernel writeback stalls.
Shutdown writes the clean marker only after accepted work and all storage are synced.

Startup discards all bytes beyond the last valid publication boundary, even complete checksummed
records that reached disk. Published records carry enough data to restore headers and compact
proofs as well as forest/leaf-map changes when application was interrupted. The applied-height
checkpoint is distinct from the published journal tip. Publication failures stop submissions and
never certify a clean shutdown; an uncertain marker flush requires reopening the journal.

On an orderly worker error, it attempts to seal and sync the leaf-map and header-index runtime
allocators before exiting; this does not advance the durable height, send notifications, or write
a clean marker. The original error and any finalization failures are preserved.

The underlying runtime database has a pre-existing crash-recovery limitation: a hard kill or
power loss during state application, before allocator sync, can leave unfinished pages or
unpublished bucket heads, and `open_runtime` may then refuse to reopen. The publication protocol
does not repair that database format. Unpublished-WAL loss and published-WAL recovery are covered
by killed-writer smoke checks; recovery during database application is covered by injected
**orderly** failures, not a guarantee of arbitrary SIGKILL or power-loss recovery.

Storage opening and crash recovery also run on named startup workers, including legacy proof-row
metadata initialization and proof truncation. Startup joins these workers before constructing the
thread-local Pollard; no recovery flush is issued by the caller.

Existing legacy journals are imported once at startup into the publication format. A permanent
initialization header distinguishes them from publication journals: a missing or corrupt marker
on an initialized journal is an error, never permission to replay an unpublished tail.
Keep `forest.journal`, `forest.journal.published`, and any `forest.journal.forest-rows` together;
do not downgrade to an older binary against the new journal format. Version-3 records store
their physical layout; older records are bound once to a checksummed `.forest-rows` sidecar
before replay or resuming a resize. An interrupted resize supplies its original row count.
Histories that already completed a resize under an older binary without layout metadata have
ambiguous journal coordinates: if the original layout is unavailable, rebuild instead of
assuming those retained records are safe to replay.

Startup validates the contiguous proof-index range after restoring available published redo data;
legacy records without proofs retain the previous proof-gap rollback policy. Reorgs durably mark
published orphan records before restoring old node states, leaf-map entries, and `numleaves`.
Pruning retains at least 144 forward records and advances the replay floor in both marker slots
before reclaiming old pages. Journal offsets stay stable; runtime compaction no longer renames
the active file. Filesystems supporting hole punching reclaim old spans; unsupported filesystems
retain those allocated bytes, but recovery skips them.

Steady state also starts a P2PV2-only BIP 183 proof server on `P2P_HOST`/`P2P_PORT`.
The `bip324` transport performs the responder handshake and encrypts every subsequent packet;
there is no P2PV1 parser or fallback. BIP 183 `uproof` and `getuproof` use short IDs 29 and 30.
The server accepts Floresta's field mask: bit 0 requests targets, bit 1 all proof hashes, and
bit 2 all leaf data (`0x07` requests everything). When an all-hashes or all-leaves bit is unset,
the corresponding bitmap selects elements least-significant-bit first; an empty bitmap selects
none. Both short-ID and long-command `getuproof` requests are supported.
Stored proof targets already use the 63-row wire layout. P2P serves them unchanged;
physical or logical forest-row metadata must not trigger another translation.
`getheaders` requests are served directly from the position-addressed header file and hash index.
Responses contain at most 2,000 headers and honor the stop hash, never advancing beyond the
committed proof-index height advertised by the version handshake. An empty locator requests only
the eligible stop header. RPC is a fallback when the flat header index is unavailable.
The version handshake advertises `NODE_WITNESS`, `NODE_P2P_V2`, and `NODE_UTREEXO`; it does not
advertise `NODE_NETWORK` or `NODE_NETWORK_LIMITED`, and block `getdata` requests are not served.
Clients must obtain blocks from a separate Bitcoin peer.

The final interoperability smoke used the actual Floresta codecs at revision
`d302d68e2e4529bf330a0d293b9e82690361d412` over an encrypted localhost connection to the bridge.
It exercised all eight field masks, multibyte bitmap selection, both command encodings,
all compact script tags, headers/stop/tip behavior, service flags, ping, and block `notfound`.
The transport regression additionally covers already-normalized high-bit targets with
27-row index metadata, which must be served unchanged.

## Building with esplora backends

You can use esplora backends to grab blocks and transactions. To do so, you'll need to enable the `esplora` feature when building the node:

```bash
cargo build --release --features esplora
```

Then, you'll need to set the `ESPLORA_URL` environment variable to the url of the esplora backend you want to use. For example:

```bash
export ESPLORA_URL=https://blockstream.info/api
```

This will reduce one requirement for running the bridge, but will make your setup slower and less secure. You'll need to trust the esplora backend to provide you with the correct blocks and transactions. We have no way to know if the esplora backend is lying to us.

The Esplora backend consumes plain hexadecimal headers and derives coinbase status from the
decoded transaction, not the status endpoint. HTTP failures, invalid hashes, and overflowing
heights propagate as errors. Backend regression tests use isolated local HTTP fixtures and do
not depend on public Esplora availability.

## Environment variables

There are a few environment variables that can be used to configure the bridge node. See .env.sample for a list of all variables.

### Features

- [x] Parallel historical forest bootstrap
- [x] Pollard-backed steady-state block proofs
- [x] P2P proof and header serving
- [x] Bitcoin Core and optional Esplora backends
- [x] Online flat-forest growth and journal recovery
- [ ] Trusted UTXO commitment for instant IBD
- [ ] Forest bootstrap transfer between bridge nodes
- [ ] Socks5 and Tor transports

## Feature flags

The `esplora` feature replaces Bitcoin Core RPC reads with an Esplora backend. The mainnet
flat-forest prover and P2P server are always compiled.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Why do we even need a bridge?

In theory, Utreexo can work without bridges. However, we need all wallets or wallet backends (e.g all electrum servers) to be Utreexo aware, generating proofs for every transaction they produce. Although this is possible, it's not trivial to do so, since we need all wallets to be updated, not only a subset.

A bridge node, although not ideal, allows us to have a few nodes that can generate proofs for the entire network. This way, even though some wallets may never implement it, we can still have utreexo nodes and wallets that can use it. If you need a bridge that's also a full node, check out [utreexod](https://github.com/utreexo/utreexod).
