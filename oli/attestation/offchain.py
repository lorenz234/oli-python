import time
import requests

class OffchainAttestations:
    def __init__(self, oli_client):
        """
        Initialize OffchainAttestations with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def create_offchain_label(self, address, chain_id, tags, ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000", retry=4):
        """
        Create an offchain OLI label attestation for a contract.
        
        Args:
            address (str): The contract address to label
            chain_id (str): Chain ID in CAIP-2 format where the address/contract resides
            tags (dict): OLI compliant tags as a dict  information (name, version, etc.)
            ref_uid (str): Reference UID
            retry (int): Number of retries for the API post request to EAS ipfs
            
        Returns:
            dict: API request response
        """
        # Check all necessary input parameters
        self.oli.validator.check_label_correctness(address, chain_id, tags, ref_uid)
        
        # Encode the label data
        data = self.oli.encoder.encode_label_data(chain_id, tags)
        
        # Build the attestation
        attestation = self.oli.attestation_base.build_offchain_attestation(
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
    
    def post_offchain_attestation(self, attestation, filename="OLI.txt"):
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
            "textJson": self.oli.json.dumps(attestation, separators=(',', ':'))
        }
        
        headers = {
            "Content-Type": "application/json"
        }
        
        # Post the data to the API
        response = requests.post(self.oli.eas_api_url, json=payload, headers=headers)
        return response
    
    def revoke_attestation(self, uid_hex, gas_limit=200000):
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
        tx_params = self.oli.attestation_base.estimate_gas_limit(function, tx_params, gas_limit)

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
    
    def multi_revoke_attestations(self, uids, gas_limit=10000000):
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
        tx_params = self.oli.attestation_base.estimate_gas_limit(function, tx_params, gas_limit)

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