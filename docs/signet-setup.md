The compose file starts a Signet Bitcoin Core node and a steady-state bridge. The bridge exposes
its P2P proof service on the configured P2P port; there is no REST service.

## Requirements

- Docker
- Docker Compose

## Usage

Generate `hints` and build the flat forest first, then place the resulting `hints`, `forest.dat`,
`leaf-map`, `headers.dat`, and `header-index` under `./bridge/`. The compose service mounts that
directory at `/app/data`.

```bash
docker-compose up
```

## Configuration

The compose file is configured to use the latest version of the bridge and
bitcoind. If you want to use a specific version, you can change the image tag
in the compose file.

You can change the exposed ports and RPC credentials with:

- `P2P_PORT`: bridge P2P port (default: 8333)
- `RPC_USER`: Bitcoin Core RPC username
- `RPC_PASSWORD`: Bitcoin Core RPC password

You can change the environment variables by creating a `.env` file in the same
directory as the compose file and setting the variables there. For example:

```bash
export P2P_PORT=8333
export RPC_USER=user
export RPC_PASSWORD=password
```

and then running:

```bash
$ source .env
$ docker-compose up
```

## Troubleshooting

If you are having problems with the bridge, you can check the logs by running:

```bash
$ docker-compose logs -f bridge
```

If you are having problems with the signet node, you can check the logs by
running:

```bash
$ docker-compose logs -f signet
```