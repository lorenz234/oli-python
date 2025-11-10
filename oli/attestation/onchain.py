class OnchainAttestations:
    def __init__(self, oli_client, private_key: str):
        """
        Initialize OnchainAttestations with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
        self.__private_key = private_key
    
    def submit_onchain_label(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", gas_limit: int=-1) -> tuple[str, str]:
        """
        Submit an OLI label as an onchain attestation to the OLI Label Pool.
        
        Args:
            address (str): The contract address to label
            chain_id (str): Chain ID in CAIP-2 format where the address/contract resides
            tags (dict): OLI compliant tags as a dict  information (name, version, etc.)
            ref_uid (str): Reference UID
            gas_limit (int): Gas limit for the transaction. If set to -1, the function will estimate the gas limit.
            
        Returns:
            str: Transaction hash
            str: UID of the attestation
        """
        # in case tag definition fails to load, skip tag formatting and validation
        if self.oli.tag_definitions is not None:

            # fix simple formatting errors in tags
            tags = self.oli.validator.fix_simple_tags_formatting(tags)

            # Check all necessary input parameters
            self.oli.validator.validate_label_correctness(address, chain_id, tags, ref_uid, auto_fix=False)

        else:
            print("Warning: OLI tag definitions not loaded, skipping tag formatting and validation. Please upgrade to the latest OLI version and ensure internet connectivity at initialization.")

        # Encode the label data
        data = self.oli.utils_other.encode_label_data(chain_id, tags)
        
        # Create the attestation
        function = self.oli.eas.functions.attest({
            'schema': self.oli.w3.to_bytes(hexstr=self.oli.oli_label_pool_schema),
            'data': {
                'recipient': self.oli.w3.to_checksum_address(address),
                'expirationTime': 0,
                'revocable': True,
                'refUID': self.oli.w3.to_bytes(hexstr=ref_uid),
                'data': self.oli.w3.to_bytes(hexstr=data),
                'value': 0
            }
        })

        # Define the transaction parameters
        tx_params = {
            'chainId': self.oli.rpc_chain_number,
            'gasPrice': self.oli.w3.eth.gas_price,
            'nonce': self.oli.w3.eth.get_transaction_count(self.oli.address),
        }

        # Estimate gas if no limit provided
        tx_params = self.oli.utils_other.estimate_gas_limit(function, tx_params, gas_limit)
        
        # Build the transaction to attest one label
        transaction = function.build_transaction(tx_params)

        # Sign the transaction with the private key
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.__private_key)
        
        # Send the transaction
        try:
            txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        except Exception as e:
            raise Exception(f"Failed to send transaction to mempool: {e}")

        # Wait for the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Check if the transaction was successful
        if txn_receipt.status == 1:
            return f"0x{txn_hash.hex()}", f"0x{txn_receipt.logs[0].data.hex()}"
        else:
            raise Exception(f"Transaction failed onchain: {txn_receipt}")

    def submit_multi_onchain_labels(self, labels: list, gas_limit: int=-1) -> tuple[str, list]:
        """
        Batch submit multiple OLI labels as an onchain attestation to the OLI Label Pool.
        
        Args:
            labels (list): List of labels, containing dictionaries with 'address', 'tags', and 'chain_id' (, optional 'ref_uid')
                address (str): The contract address to label
                chain_id (str): Chain ID in CAIP-2 format where the address/contract resides
                tags (dict): OLI compliant tags as a dict  information (name, version, etc.)
                ref_uid (str): Reference UID
            gas_limit (int): Gas limit for one transaction to submit all labels passed, make sure to set it high enough for multiple attestations! If set to -1, the function will estimate the gas limit.
            
        Returns:
            str: Transaction hash
            list: List of UID of the attestation
        """
        # Prepare the list of "data" requests
        full_data = []
        for label in labels:
            # check if address, chain_id & tags are provided
            if 'chain_id' not in label:
                raise ValueError("chain_id must be provided for each label in CAIP-2 format (e.g., Base -> 'eip155:8453')")
            elif 'address' not in label:
                raise ValueError("An address must be provided for each label")
            elif 'tags' not in label:
                raise ValueError("tags dictionary must be provided for each label")
            
            # in case tag definition fails to load, skip tag formatting and validation
            if self.oli.tag_definitions is not None:
                
                # fix simple formatting errors in tags
                label['tags'] = self.oli.validator.fix_simple_tags_formatting(label['tags'])

                # run checks on each label
                self.oli.validator.validate_label_correctness(label['address'], label['chain_id'], label['tags'], auto_fix=False)

            else:
                print("Warning: OLI tag definitions not loaded, skipping tag formatting and validation. Please upgrade to the latest OLI version and ensure internet connectivity at initialization.")

            # check if ref_uid is provided
            if 'ref_uid' not in label:
                label['ref_uid'] = "0x0000000000000000000000000000000000000000000000000000000000000000"
            else:
                self.oli.validator.validate_ref_uid(label['ref_uid'])

            # ABI encode data for each attestation
            data = self.oli.utils_other.encode_label_data(label['chain_id'], label['tags'])
            full_data.append({
                'recipient': self.oli.w3.to_checksum_address(label['address']),
                'expirationTime': 0,
                'revocable': True,
                'refUID': self.oli.w3.to_bytes(hexstr=label['ref_uid']),
                'data': self.oli.w3.to_bytes(hexstr=data),
                'value': 0
            })

        # Create the multi-attestation request
        multi_requests = [{
            'schema': self.oli.w3.to_bytes(hexstr=self.oli.oli_label_pool_schema),
            'data': full_data
        }]

        # Create the function call
        function = self.oli.eas.functions.multiAttest(multi_requests)

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

        # Sign the transaction with the private key
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.__private_key)
        
        # Send the transaction
        try:
            txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        except Exception as e:
            raise Exception(f"Failed to send transaction to mempool: {e}")
        
        # Wait for the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)

        # Check if the transaction was successful
        if txn_receipt.status != 1:
            raise Exception(f"Transaction failed onchain: {txn_receipt}")

        # log the UIDs of the attestations in a list
        uids = ['0x' + log.data.hex() for log in txn_receipt.logs]

        return f"0x{txn_hash.hex()}", uids

    def submit_onchain_trust_list(self, owner: str, trusted: list, untrusted: list, gas_limit: int=-1) -> tuple[str, str]:
        """
        Submit an OLI trust list as an onchain attestation to the OLI Trust List Pool.
        
        Args:
            owner (str): The address of the owner of the trust list
            trusted (list): List of dictionaries containing trusted addresses
            untrusted (list): List of dictionaries containing untrusted addresses
            gas_limit (int): Gas limit for the transaction. If set to -1, the function will estimate the gas limit.

        Returns:
            str: Transaction hash
            str: UID of the attestation
        """
        # Validate the trust list
        self.oli.validator.validate_trust_list_correctness(owner, trusted, untrusted)

        # Encode the label data
        data = self.oli.utils_other.encode_list_data(owner, trusted, untrusted)
        
        # Create the attestation
        function = self.oli.eas.functions.attest({
            'schema': self.oli.w3.to_bytes(hexstr=self.oli.oli_label_trust_schema),
            'data': {
                'recipient': "0x0000000000000000000000000000000000000000",  # Trust lists are not tied to a specific address
                'expirationTime': 0, # never expires
                'revocable': True, # can be revoked
                'refUID': "0x0000000000000000000000000000000000000000000000000000000000000000", # no ref UID for trust lists
                'data': self.oli.w3.to_bytes(hexstr=data),
                'value': 0
            }
        })

        # Define the transaction parameters
        tx_params = {
            'chainId': self.oli.rpc_chain_number,
            'gasPrice': self.oli.w3.eth.gas_price,
            'nonce': self.oli.w3.eth.get_transaction_count(self.oli.address),
        }

        # Estimate gas if no limit provided
        tx_params = self.oli.utils_other.estimate_gas_limit(function, tx_params, gas_limit)
        
        # Build the transaction to attest one label
        transaction = function.build_transaction(tx_params)

        # Sign the transaction with the private key
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.__private_key)
        
        # Send the transaction
        try:
            txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)
        except Exception as e:
            raise Exception(f"Failed to send transaction to mempool: {e}")

        # Wait for the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Check if the transaction was successful
        if txn_receipt.status == 1:
            return f"0x{txn_hash.hex()}", f"0x{txn_receipt.logs[0].data.hex()}"
        else:
            raise Exception(f"Transaction failed onchain: {txn_receipt}")

    def revoke_attestation(self, uid_hex: str, gas_limit: int=200000) -> str:
        """
        Revoke an onchain attestation using its UID.
        
        Args:
            uid_hex (str): UID of the attestation to revoke (in hex format)
            gas_limit (int): Gas limit for the transaction. If not set, defaults to 200000. Gas estimation is not possible for revoke transactions.
            
        Returns:
            str: Transaction hash
        """
        function = self.oli.eas.functions.revoke({
            'schema': self.oli.w3.to_bytes(hexstr=self.oli.oli_label_pool_schema),
            'data': {
                'uid': self.oli.w3.to_bytes(hexstr=uid_hex),
                'value': 0
            }
        })

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
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.__private_key)

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
    
    def multi_revoke_attestations(self, uids: list, gas_limit: int=10000000) -> tuple[str, int]:
        """
        Revoke multiple onchain attestations in a single transaction.
        
        Args:
            uids (list): List of UIDs to revoke (in hex format)
            gas_limit (int): Gas limit for the transaction. If not set, defaults to 10000000. Gas estimation is not possible for revoke transactions.
            
        Returns:
            str: Transaction hash
            int: Number of attestations revoked
        """
        revocation_data = []
        for uid in uids:
            revocation_data.append({
                'uid': self.oli.w3.to_bytes(hexstr=uid),
                'value': 0
            })
        multi_requests = [{
            'schema': self.oli.w3.to_bytes(hexstr=self.oli.oli_label_pool_schema),
            'data': revocation_data
        }]
        function = self.oli.eas.functions.multiRevoke(multi_requests)

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
        signed_txn = self.oli.w3.eth.account.sign_transaction(transaction, private_key=self.__private_key)

        # Send the transaction
        txn_hash = self.oli.w3.eth.send_raw_transaction(signed_txn.raw_transaction)

        # Get the transaction receipt
        txn_receipt = self.oli.w3.eth.wait_for_transaction_receipt(txn_hash)
        
        # Check if the transaction was successful
        if txn_receipt.status == 1:
            return f"0x{txn_hash.hex()}"
        else:
            raise Exception(f"Transaction failed: {txn_receipt}")