## Bridge

This is a special propose Bridge node. Bridges are Bitcoin nodes that holds the entire UTXO set in a forest, allowing it to generate proofs in place for blocks and transactions. The goal with this node is provide a simple and efficient tool to generate proofs for the Bitcoin network.

It contains multiple components:

    - A Bitcoin node that accepts connections from other nodes and clients and can serve proofs for blocks and transactions.
    - A REST API that can be used to query the node for proofs.
    - A websocket that serves as lightweight replacement to the bitcoin p2p. It notifies clients about new blocks, sending the necessary proofs.
    - The actual proof generation code.

## Installation

### Requirements

- Rust 1.85.0 or later
- Linux x86-64
- A C++ toolchain, CMake, and Boost to compile `rust-bitcoinkernel`
- Because just keep things on RAM, you'll need a machine with at least 16GB of RAM.
- At least 500GB of free disk space, 1TB recommended.
- A trusted source of blocks to connect to. You can use Bitcoin Core.

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

## Using

### Running the node

This bridge node doesn't perform any validation on the blocks, so you'll need a trusted source of blocks to connect to. You can use the [Bitcoin Core](https://github.com/bitcoin/bitcoin) node to connect to grab blocks from. This is the only dependency of the node.
Assuming you have a Bitcoin node running, just start the bridge as follows:

```bash
./target/release/bridge
```

The bridge will start listening on port 8333 for incoming connections from other nodes and clients. It will also start a websocket server on port 8334. API runs on port 8335. See [the API docs](docs/API.md) for more information.

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
outputs at heights 91,722 and 91,812 are excluded before the index is incremented. The completed
hintsfile is encoded to a temporary file and atomically moved into place.

### Parallel flat-forest bootstrap

Linux builds can construct the historical forest directly in a preallocated, memory-mapped flat
file. The hintsfile stop height is the build target:

```bash
./target/release/bridge \
    --network signet \
    --build-forest /path/to/utxo.hints \
    --forest-file /path/to/forest.dat \
    --leaf-map-path /path/to/leaf-map
```

The leaf map defaults to `$DATA_DIR/leaf-map`. Its directory must not already exist.

`--forest-leaf-workers` and `--forest-chaser-workers` override the default half-CPU split.
`--forest-spin-iterations` controls how long chasers spin before sleeping on the publication
condition variable.
Leaf fetchers take four-height chunks in round-robin order: each worker processes one adjacent
chunk, jumps past the other workers' chunks, then repeats. No worker owns a fixed chain range.

The builder first reads blocks once to determine deterministic leaf offsets, then reads them
concurrently again through Core's kernel chainstate while writing leaves. Each leaf-fetching
thread writes the leaf to the forest and concurrently inserts every unspent outpoint into the
leaf map. Hints indices are interpreted over Utreexo-eligible outputs in block order; provably
unspendable outputs and outputs consumed in their creating block are excluded.
Chasers own deterministic ranges, each covering at least two input pages except
where an entire upper row is smaller. A deleted child promotes its surviving sibling to the
parent; two deleted children mark the parent deleted, recursively promoting surviving subtrees
through roots. Independent ranges apply these rules concurrently with leaf publication.

Leaf-map keys are the 32-byte internal txid followed by little-endian `vout`; values are
little-endian `u64` bottom-row positions. Only unspent leaves are indexed. A promoted leaf keeps
its original bottom-row value permanently—the parent chasers never update the map. On clean
completion, the mutable runtime files are synced and closed directly; no checkpoint snapshot is
created. Crash recovery for interrupted builds is intentionally deferred.

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

- [x] Proof generation for blocks
- [x] Proof generation for individual transactions
- [x] Use other backends than bitcoin core (you can use esplora backends, like blockstream.info/api and mempool.space/api)
- [ ] Batch proof generation for individual utxos (not in the same tx)
- [ ] Spend proofs
- [ ] Proof generation for mempool transactions
- [x] API
- [ ] Websocket
- [x] P2P
- [ ] Trusted utxo commitment for instant ibd
- [ ] Lease the accumulated utxo set to other nodes (fast bridge bootstrapping)
- [ ] Support for pruning
- [ ] Support for pruning with checkpoints
- [ ] Leaf caches should allow for disk persistence, so we can reduce memory usage without needing to ask for utxos again.
- [ ] Rustreexo should allow for in disk forest.
- [ ] Support for socks5 proxy
- [ ] Support for tor onion services
- [x] Support for ipv6
- [ ] Push roots over nostr on every block
- [ ] ... and more ...

## Feature flags

We have a few feature flags that can be used to enable or disable some features of the bridge node. Here's a list of all available feature flags:
 - `esplora`: Enables the use of esplora backends to grab blocks and transactions. This can replace the usage of Bitcoin Core as a backend.
 - `node`: Enables a small p2p node that will serve blocks and transactions over the network to other nodes and clients.
 - `api`: Enables the REST API that can be used to query the node for proofs.
 - `shinigami`: This feature is used to enable compatibility with [starknet's Cairo prover](https://github.com/keep-starknet-strange/raito/) for the Bitcoin protocol. This will disable the node and API, use Poseidon as the accumulator hash function and save data in JSON files.

The deafult features are `bitcoin`, `node` and `api`. To change this, you can use the `--no-default-features` flag when building the node. For example, to build with the `shinigami` feature, you can use the following command:

```bash
cargo build --release --no-default-features --features shinigami
```

If you don't provide either `bitcoin` or `shinigami`, you'll have a compile error. You also can't use both at the same time. The API and node,
currently, are not compatible with the `shinigami` feature.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details

## Why do we even need a bridge?

In theory, Utreexo can work without bridges. However, we need all wallets or wallet backends (e.g all electrum servers) to be Utreexo aware, generating proofs for every transaction they produce. Although this is possible, it's not trivial to do so, since we need all wallets to be updated, not only a subset.

A bridge node, although not ideal, allows us to have a few nodes that can generate proofs for the entire network. This way, even though some wallets may never implement it, we can still have utreexo nodes and wallets that can use it. If you need a bridge that's also a full node, check out [utreexod](https://github.com/utreexo/utreexod).
