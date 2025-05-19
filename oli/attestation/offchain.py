import time
import requests
import secrets
import json
from requests import Response

class OffchainAttestations:
    def __init__(self, oli_client):
        """
        Initialize OffchainAttestations with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def submit_offchain_label(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", retry: int=4):
        """
        Submit an OLI label as an offchain attestation to the OLI Label Pool.
        
        Args:
            address (str): The contract address to label
            chain_id (str): Chain ID in CAIP-2 format where the address/contract resides
            tags (dict): OLI compliant tags as a dict  information (name, version, etc.)
            ref_uid (str): Reference UID
            retry (int): Number of retries for the API post request to EAS ipfs
            
        Returns:
            dict: API request response
        """
        # fix simple formatting errors in tags
        tags = self.oli.validator.fix_simple_tags_formatting(tags)

        # Check all necessary input parameters
        self.oli.validator.validate_label_correctness(address, chain_id, tags, ref_uid, auto_fix=False)
        
        # Encode the label data
        data = self.oli.utils_other.encode_label_data(chain_id, tags)
        
        # Build the attestation
        attestation = self.build_offchain_attestation(
            recipient=address, 
            schema=self.oli.oli_label_pool_schema, 
            data=data, 
            ref_uid=ref_uid
        )
        
        # Post to the API & retry if status code is not 200
        response = self.post_offchain_attestation(attestation)
        n0 = retry
        while response.status_code != 200 and retry > 0:
            retry -= 1
            time.sleep(2 ** (n0 - retry)) # exponential backoff
            response = self.post_offchain_attestation(attestation)
        
        # if it fails after all retries, raise an error
        if response.status_code != 200:
            raise Exception(f"Failed to submit offchain attestation to EAS API ipfs post endpoint after {n0} retries: {response.status_code} - {response.text}")

        return response
    
    def post_offchain_attestation(self, attestation: dict, filename: str="OLI.txt") -> Response:
        """
        Post API an attestation to the EAS API.
        
        Args:
            attestation (dict): The attestation package
            filename (str): Custom filename
            
        Returns:
            dict: API response
        """
        # Convert numerical values to strings for JSON serialization
        attestation["sig"]["message"]["time"] = str(attestation["sig"]["message"]["time"])
        attestation["sig"]["message"]["expirationTime"] = str(attestation["sig"]["message"]["expirationTime"])
        attestation["sig"]["domain"]["chainId"] = str(attestation["sig"]["domain"]["chainId"])
        
        # Prepare payload for the API endpoint
        payload = {
            "filename": filename,
            "textJson": json.dumps(attestation, separators=(',', ':'))
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        # Post the data to the API
        response = requests.post(self.oli.eas_api_url, json=payload, headers=headers)
        return response
    
    def build_offchain_attestation(self, recipient: str, schema: str, data: str, ref_uid: str, revocable: bool=True, expiration_time: int=0) -> dict:
        """
        Build an offchain attestation with the given parameters.
        
        Args:
            recipient (str): Ethereum address of the contract to be labeled
            schema (str): Schema hash
            data (str): Hex-encoded data
            ref_uid (str): Reference UID
            revocable (bool): Whether the attestation is revocable
            expiration_time (int): Expiration time in seconds since epoch
            
        Returns:
            dict: The signed attestation and UID
        """
        # Create a random salt
        salt = f"0x{secrets.token_hex(32)}"
        
        # Current time in seconds
        current_time = int(time.time())
        
        # Typed data for the attestation
        typed_data = {
            "version": 2,
            "recipient": recipient,
            "time": current_time,
            "revocable": revocable,
            "schema": schema,
            "refUID": ref_uid,
            "data": data,
            "expirationTime": expiration_time,
            "salt": salt,
        }
        
        # EIP-712 typed data format
        types = {
            "domain": {
                "name": "EAS Attestation",
                "version": "1.2.0",
                "chainId": self.oli.rpc_chain_number,
                "verifyingContract": self.oli.eas_address
            },
            "primaryType": "Attest",
            "message": typed_data,
            "types": {
                "Attest": [
                    {"name": "version", "type": "uint16"},
                    {"name": "schema", "type": "bytes32"},
                    {"name": "recipient", "type": "address"},
                    {"name": "time", "type": "uint64"},
                    {"name": "expirationTime", "type": "uint64"},
                    {"name": "revocable", "type": "bool"},
                    {"name": "refUID", "type": "bytes32"},
                    {"name": "data", "type": "bytes"},
                    {"name": "salt", "type": "bytes32"}
                ]
            }
        }

        # Sign the message using the account
        signed_message = self.oli.account.sign_typed_data(
            domain_data=types["domain"],
            message_types=types["types"],
            message_data=typed_data
        )
        
        # Calculate the UID
        attester = '0x0000000000000000000000000000000000000000'  # for offchain UID calculation
        uid = self.oli.utils_other.calculate_attestation_uid_v2(
            schema, recipient, attester, current_time, data, 
            expiration_time, revocable, ref_uid, salt=salt
        )
        uid_hex = '0x' + uid.hex()
        
        # Package the result
        result = {
            "sig": {
                "domain": types["domain"],
                "primaryType": types["primaryType"],
                "types": types["types"],
                "message": typed_data,
                "uid": uid_hex,
                "version": 2,
                "signature": {
                    "r": hex(signed_message.r),
                    "s": hex(signed_message.s),
                    "v": signed_message.v
                }
            },
            "signer": self.oli.address
        }
        
        return result
    
    def revoke_attestation(self, uid_hex: str, gas_limit: int=200000):
        """
        Revoke an offchain attestation using its UID.
        
        Args:
            uid_hex (str): UID of the attestation to revoke (in hex format)
            gas_limit (int): Gas limit for the transaction. If not set, defaults to 200000. Gas estimation is not possible for revoke transactions.
            
        Returns:
            str: Transaction hash
        """
        function = self.oli.eas.functions.revokeOffchain(self.oli.w3.to_bytes(hexstr=uid_hex))

        # Define the transaction parameters
        tx_params = {
            'chainId': self.oli.rpc_chain_number,
            'gasPrice': self.oli.w3.eth.gas_price,
            'nonce': self.oli.w3.eth.get_transaction_count(self.oli.address),
        }

        # Estimate gas if no limit provided
        tx_params = self.oli.utils_other.estimate_gas_limit(function, tx_params, gas_limit)

        # Build the transaction to revoke an attestation
        transaction = function.build_transaction(tx_params)

        # Sign the transaction
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.oli.private_key)

        # Send the transaction
        try:
            txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        except Exception as e:
            raise Exception(f"Failed to send revoke transaction to mempool: {e}")

        # Get the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Check if the transaction was successful
        if txn_receipt.status == 1:
            return f"0x{txn_hash.hex()}"
        else:
            raise Exception(f"Transaction failed: {txn_receipt}")
    
    def multi_revoke_attestations(self, uids: str, gas_limit: int=10000000):
        """
        Revoke multiple offchain attestations in a single transaction.
        
        Args:
            uids (list): List of UIDs to revoke (in hex format)
            gas_limit (int): Gas limit for the transaction. If not set, defaults to 10000000. Gas estimation is not possible for revoke transactions.
            
        Returns:
            str: Transaction hash
            int: Number of attestations revoked
        """
        revocation_data = []
        for uid in uids:
            revocation_data.append(self.oli.w3.to_bytes(hexstr=uid))
        function = self.oli.eas.functions.multiRevokeOffchain(revocation_data)

        # Define the transaction parameters
        tx_params = {
            'chainId': self.oli.rpc_chain_number,
            'gasPrice': self.oli.w3.eth.gas_price,
            'nonce': self.oli.w3.eth.get_transaction_count(self.oli.address),
        }

        # Estimate gas if no limit provided
        tx_params = self.oli.utils_other.estimate_gas_limit(function, tx_params, gas_limit)

        # Build the transaction
        transaction = function.build_transaction(tx_params)

        # Sign the transaction
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.oli.private_key)

        # Send the transaction
        txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        # Get the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Check if the transaction was successful
        if txn_receipt.status == 1:
            return f"0x{txn_hash.hex()}", len(uids)
        else:
            raise Exception(f"Transaction failed: {txn_receipt}")