## Bridge

This bridge maintains the Bitcoin UTXO accumulator and produces compact proofs for new blocks. It bootstraps from Bitcoin Core and then serves proofs to Utreexo-aware peers.

It contains three components:

- A parallel bootstrap builder for the historical flat forest, leaf map, and header index.
- A Pollard-backed steady-state prover that persists compact block proofs.
- A BIP324 P2PV2-only Bitcoin server that serves BIP183 block inclusion proofs and headers.

## Installation

### Requirements

- Rust 1.89.0 or later (required by the local database's batch implementation)
- Linux x86-64
- A C++ toolchain, CMake, and Boost to compile `rust-bitcoinkernel`
- Because just keep things on RAM, you'll need a machine with at least 16GB of RAM.
- At least 500GB of free disk space, 1TB recommended.
- A trusted source of blocks to connect to. You can use Bitcoin Core.
- Sibling `../ultra-fast-database` (`floresta-db`) and `../rustreexo` checkouts.
  The accumulator checkout must include the bridge's position-addressed Pollard
  cache APIs (the local `bridge` branch); an upstream-only checkout is insufficient.

### From source

```bash
git clone https://github.com/Davidson-Souza/bridge
cd bridge
cargo build --release
```

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
persistent leaf map or rereading the leaf hash. Cache misses first wait for the
background flusher, then resolve together through one ordered `batch_fetch`.
The Pollard reports uncached target and proof
positions, and only those hashes are read from the flat forest and ingested. The Pollard is
modified immediately and is the source of truth while journal records are pending.
`--pollard-memory-mib` sets its cache quota and defaults to 250 MiB. Before cached leaves are
reclaimed, pending forest writes are flushed so a later miss cannot observe stale state.

Per-block cache metrics, foreground timings, and completed background-apply timings are written at
debug level to `$DATA_DIR/debug.log`. Terminal logs report block height, hash, proof size, and
important lifecycle events without timing noise.

The persistent leaf map continues to hold stable bottom positions. Only forest-node changes from
journal entries awaiting the background worker are overlaid in the foreground; position-index
changes remain exclusively inside Pollard until the worker updates the persistent map. Pollard
proof generation maps bottom positions into the promoted sparse forest, including promotions
above live branches. The runtime map is given 1 GiB of append headroom; older bootstrap maps are
extended in place before they are opened.

Journal application and rollback use `batch_delete` and `put_batch`. They remove
the union of affected keys before reinsertion so replay remains idempotent even
though the database's append-only batch writer retains duplicate keys.

After applying each steady-state block with `height % 1_000 == 0`, the background
worker compacts leaf-map pages below half occupancy (16,384 live nodes per
1 MiB page), then syncs the forest and database before publishing completion.
The worker owns the forest exclusively during deletion and compaction; foreground
lookups cannot retain stale node offsets. Compaction failures abort the apply
job rather than marking the height durable. Header reads and steady-state index
replacement/removal are coordinated separately by a read/write lock.

Online growth doubles the bottom-row capacity without restarting the bridge. Pending journal
applications are drained first, internal rows are relocated into the enlarged positional layout,
and the newly exposed bottom positions are cleared before proving continues. A durable
`forest.resize` sidecar records the relocation phase; startup resumes an interrupted resize before
opening the steady-state forest. Proof-index entries retain the logical row count used by their
targets, so proofs created before and after a resize remain wire-compatible.

Post-hints proofs are appended to `$DATA_DIR/proofs` and indexed by block hash under
`$DATA_DIR/proof-index`. Records contain only targets, proof hashes, and compact leaf data—Bitcoin
blocks are fetched from Core and are not retained.

Every steady-state block is published first to `$DATA_DIR/forest.journal`. A page-aligned record
starts with the block hash and post-block `numleaves`, then contains every changed forest position
with its before/after hash and publication/spent flags. Added and removed outpoints include their
stable bottom positions. The foreground writer completes the header, payload, checksum, and
trailer before release-storing the new published journal size. No journal lock is shared with the
background flusher. An acquire load prevents that worker from observing a partial record.

The foreground hands exclusive ownership of the forest to one background apply job; no forest
mutex is shared between the threads. While that worker flushes the journal and applies and syncs
the forest and leaf map, the foreground persists the proof, header, and proof index. The next block
does not begin until ownership returns and the completed height is durably published.

Startup validates the contiguous proof-index range, reconstructs the retained journal window, and
refuses to advance across a missing proof. Reorgs durably mark orphan records before restoring old
node states, leaf-map entries, and `numleaves`. The journal retains 144 forward records. Older spans
use hole punching when supported and durable tombstones otherwise.

Steady state also starts a P2PV2-only BIP 183 proof server on `P2P_HOST`/`P2P_PORT`.
The `bip324` transport performs the responder handshake and encrypts every subsequent packet;
there is no P2PV1 parser or fallback. BIP 183 `uproof` and `getuproof` use short IDs 29 and 30.
The server accepts Floresta's field mask and least-significant-bit-first proof/leaf bitmaps, then
replies with proof hashes, targets, and compact leaf data. Empty bitmaps request every element.
`getheaders` requests are served directly from the position-addressed header file and hash index.
Responses contain at most 2,000 headers and honor the stop hash. RPC is only a compatibility
fallback for normal-mode databases without the flat header index.
The version handshake advertises `NODE_WITNESS`, `NODE_P2P_V2`, and `NODE_UTREEXO`; it does not
advertise `NODE_NETWORK` or `NODE_NETWORK_LIMITED`, and block `getdata` requests are not served.
Clients must obtain blocks from a separate Bitcoin peer.

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
