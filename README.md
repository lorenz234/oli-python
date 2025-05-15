# OLI Python Package

A Python client for interacting with the Open Labels Initiative (OLI) on the Base blockchain.

## Installation

```bash
pip install oli-python
```

## Basic Usage

```python
from oli_python import OLI

# Initialize the client (production=True for mainnet, False for testnet)
oli = OLI(private_key="YOUR_PRIVATE_KEY", is_production=True)

# Create an offchain label
address = "0x1234567890123456789012345678901234567890"
chain_id = "eip155:8453"  # Base
tags = {
    "contract_name": "Example Contract",
    "is_eoa": False,
    "usage_category": "defi"
}

# Create an offchain attestation
response = oli.create_offchain_label(address, chain_id, tags)
print(f"Attestation created: {response.status_code}")

# Create an onchain attestation
tx_hash, uid = oli.create_onchain_label(address, chain_id, tags)
print(f"Transaction hash: {tx_hash}")
print(f"Attestation UID: {uid}")

# Query attestations for a specific address
result = oli.graphql_query_attestations(address=address)
print(result)
```

## Features

- Create onchain and offchain OLI labels
- Batch create multiple labels in a single transaction
- Revoke attestations
- Query attestations using GraphQL
- Download full dataset exports in Parquet format

## Documentation

For more details, see the [OLI Documentation](https://github.com/openlabelsinitiative/OLI).

## License

MIT