# OLI Python Package

Python SDK for interacting with the Open Labels Initiative; A framework for address labels in the blockchain space. Read & write labels into the OLI Label Pool, check your labels for OLI compliance.

## Installation

```bash
pip install oli-python
```

### Submitting New Labels

```python
from oli import OLI
import os

# Initialize the client
# Make sure to pull in your private key from an .env file
oli = OLI(private_key=os.environ['OLI_PRIVATE_KEY'], is_production=True)

# Create a label
address = "0x9438b8B447179740cD97869997a2FCc9b4AA63a2"
chain_id = "eip155:1" # Ethereum Mainnet
tags = {
    "contract_name": "growthepie donation address",
    "is_eoa": True,
    "owner_project": "growthepie"
}

# Validate if your label is OLI compliant
possible_to_attest = oli.validate_label_correctness(address, chain_id, tags)
print(f"You can attest your label: {possible_to_attest}")

# Submit a label as an offchain attestation
response = oli.submit_offchain_label(address, chain_id, tags)
print(f"Label submitted offchain with response: {response.text}")

# Submit a label as an onchain attestation
tx_hash, uid = oli.submit_onchain_label(address, chain_id, tags)
print(f"Label submitted onchain with hash: {tx_hash} and uid: {uid}")

# Batch submit multiple labels as one onchain attestation
labels = [
    {'address': address, 'chain_id': chain_id, 'tags': tags},
    {'address': address, 'chain_id': chain_id, 'tags': tags}
]
tx_hash, uids = oli.submit_multi_onchain_labels(labels)
print(f"Labels batch submitted onchain with transaction hash: {tx_hash} and uids: {uids}")

# Revoke an attestation (revoking onchain attestations here)
trx_hash = oli.revoke_attestation(uid, onchain=True)
print(f"Label {uid} revoked with hash: {trx_hash}")

# Revoke multiple attestations (revoking onchain attestations here)
trx_hash, count = oli.multi_revoke_attestations(uids, onchain=True)
print(f"Labels batch revoked with hash: {trx_hash}")

```

### Querying Existing Labels

```python
from oli import OLI
import os

# Initialize the client (read mode only doesn't require a private key)
oli = OLI()

# Query attestations for a specific address
result = oli.graphql_query_attestations(address=address)
print(result)

# Download parquet export of raw attestations
oli.get_full_raw_export_parquet()

# Download parquet export of decoded attestations
oli.get_full_decoded_export_parquet()
```


## Wallet Requirements

The [OLI Label Pool](https://github.com/openlabelsinitiative/OLI/tree/main/2_label_pool) lives on Base as an [Ethereum Attestation schema](https://base.easscan.org/schema/view/0xb763e62d940bed6f527dd82418e146a904e62a297b8fa765c9b3e1f0bc6fdd68). 

Make sure your wallet contains ETH on **Base Mainnet** to pay for onchain transaction (including offchain revocations). Offchain attestations are free.

For testing purposes, you can use Base Sepolia Testnet by setting `is_production=False` when initializing the client.

## Features

- Submit onchain (single or batch) and offchain (single) labels into the OLI Label Pool
- Revoke your own labels (single or batch)
- Validate if your label is OLI compliant
- Query attestations using GraphQL
- Download full dataset exports in Parquet format

## Documentation

For more details, see the [OLI Documentation](https://github.com/openlabelsinitiative/OLI).

## License

MIT