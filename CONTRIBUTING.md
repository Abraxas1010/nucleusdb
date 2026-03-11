# Contributing to NucleusDB

## Scope

This repository is the standalone NucleusDB product. Contributions should strengthen one of these surfaces:

- verifiable database core
- SQL and typed-value execution
- append-only / monotone-seal behavior
- Discord recording
- MCP server
- dashboard and deployment surfaces
- Lean formal NucleusDB proofs

Contributions that expand scope beyond these surfaces require explicit project discussion first.

## Development

```bash
cargo check --bin nucleusdb --bin nucleusdb-mcp --bin nucleusdb-discord --bin nucleusdb-server --bin nucleusdb-tui
cargo test
```

If you change dashboard assets, rebuild before claiming the frontend changed.

## Pull Requests

Please include:

- the problem being solved
- the affected modules
- the commands you used to verify the change
- any intentionally deferred work

## Security

Treat Discord tokens, environment files, and encrypted local storage as sensitive. Never commit live credentials. See [SECURITY.md](SECURITY.md).
