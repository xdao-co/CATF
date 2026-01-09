# xDAO CATF

- Reference design: [ReferenceDesign.md](ReferenceDesign.md)
- CLI how-to: [CLI.md](CLI.md)
- End-to-end workflows: [UseCases.md](UseCases.md)
- Runnable scripts: [examples/README.md](examples/README.md)

## IPFS note (local vs network publishing)

- The reference workflows assume your local node (e.g. an XDAO Node) has the Kubo `ipfs` CLI installed.
- `doc-cid` only computes a CID (content-addressing); it does not publish bytes.
- `ipfs put` stores bytes into the local IPFS repo without requiring a daemon.
- If you intend to publish to the IPFS network “for real” (so other peers can fetch it), your node must be running in daemon mode (`ipfs daemon`) and the content must be provided/pinned by that node.
