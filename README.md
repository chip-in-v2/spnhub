# spnhub

Component of the SPN (Service Provider Network) infrastructure: a secure, virtualized distribution network for enterprise applications. `spnhub` is the core server component that orchestrates the network.

## Overview
`spnhub` functions as the backbone of the SPN virtual network. It operates based on configuration data fetched from a `chip-in inventory` server, which serves as the single source of truth for the network topology and security policies.

## Key Roles
- **Network Orchestration**: Manages virtual connections between providers and consumers.
- **Dynamic Routing**: Handles service discovery and traffic mediation within the SPN.
- **Security**: Validates identities based on inventory definitions.

## Configuration (Environment Variables)
- `SPNHUB_INVENTORY_URL`: URL of the chip-in inventory server (supports `http(s)://` or `file://`).
- `RUST_LOG`: Log level (e.g., `info`, `debug`).

## Public Interface
- **UDP (Inbound)**: Listening port for `spnagent` connections (Address and Port are defined within the inventory configuration).

## Deployment
- **Binary**: Static `musl` binaries available in Releases.
- **Container**: Lightweight `scratch`-based images available in Packages.
- **Platforms**: Compatible with Nomad, Kubernetes (K8s), and bare-metal environments.