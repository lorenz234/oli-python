import secrets
import time
from web3 import Web3

class AttestationBase:
    def __init__(self, oli_client):
        """
        Initialize the AttestationBase with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def estimate_gas_limit(self, function, tx_params, gas_limit):
        """
        Estimate gas for a transaction.
        
        Args:
            function: The function to estimate gas for
            tx_params (dict): Transaction parameters
            gas_limit (int): Gas limit
            
        Returns:
            tx_params (dict): Transaction parameters with estimated 'gas' field
        """
        try:
            if gas_limit == 0:
                # Estimate gas with a buffer (e.g., 10% more than the estimate)
                estimated_gas = function.estimate_gas(tx_params)
                tx_params["gas"] = int(estimated_gas * 1.1)  # Add 10% buffer
            else:
                tx_params["gas"] = gas_limit
        except Exception as e:
            tx_params["gas"] = 10000000  # Default fallback
        return tx_params
    
    def build_offchain_attestation(self, recipient, schema, data, ref_uid, revocable=True, expiration_time=0):
        """
        Build an attestation with the given parameters.
        
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
        uid = self.calculate_attestation_uid_v2(
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
    
    def calculate_attestation_uid_v2(self, schema, recipient, attester, timestamp, data, expiration_time=0, revocable=True, ref_uid="0x0000000000000000000000000000000000000000000000000000000000000000", bump=0, salt=None):
        """
        Calculate the UID for an offchain attestation (v2).
        
        Args:
            schema (str): Schema hash
            recipient (str): Recipient address
            attester (str): Attester address
            timestamp (int): Timestamp
            data (str): Attestation data
            expiration_time (int): Expiration time
            revocable (bool): Whether attestation is revocable
            ref_uid (str): Reference UID
            bump (int): Bump value
            salt (str): Salt value
            
        Returns:
            bytes: The calculated UID
        """
        # Generate salt if not provided
        if salt is None:
            salt = f"0x{secrets.token_hex(32)}"
            
        # Version
        version = 2
        version_bytes = version.to_bytes(2, byteorder='big')
        
        # Handle schema formatting
        if not schema.startswith('0x'):
            schema = '0x' + schema
        schema_utf8_bytes = schema.encode('utf-8')
        schema_bytes = schema_utf8_bytes
        
        # Convert values to bytes
        recipient_bytes = Web3.to_bytes(hexstr=recipient)
        attester_bytes = Web3.to_bytes(hexstr=attester)
        timestamp_bytes = timestamp.to_bytes(8, byteorder='big')
        expiration_bytes = expiration_time.to_bytes(8, byteorder='big')
        revocable_bytes = bytes([1]) if revocable else bytes([0])
        ref_uid_bytes = Web3.to_bytes(hexstr=ref_uid)
        data_bytes = Web3.to_bytes(hexstr=data)
        salt_bytes = Web3.to_bytes(hexstr=salt)
        bump_bytes = bump.to_bytes(4, byteorder='big')
        
        # Pack all values
        packed_data = (
            version_bytes + schema_bytes + recipient_bytes + attester_bytes + 
            timestamp_bytes + expiration_bytes + revocable_bytes + ref_uid_bytes + 
            data_bytes + salt_bytes + bump_bytes
        )
        
        # Calculate keccak256 hash
        uid = Web3.keccak(packed_data)
        return uid