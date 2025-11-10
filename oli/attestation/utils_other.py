import json
from eth_abi.abi import encode
import secrets
from web3 import Web3

class UtilsOther:
    def __init__(self, oli_client):
        """
        Initialize the DataEncoder with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def encode_label_data(self, chain_id: str, tags_json: dict) -> str:
        """
        Encode label data in the OLI format.
        
        Args:
            chain_id (str): Chain ID in CAIP-2 format of the label (e.g. 'eip155:8453')
            tags_json (dict): Dictionary of tag data following the OLI format
            
        Returns:
            str: Hex-encoded ABI data
        """
        # Convert dict to JSON string if needed
        if isinstance(tags_json, dict):
            tags_json = json.dumps(tags_json)
            
        # ABI encode the data
        encoded_data = encode(['string', 'string'], [chain_id, tags_json])
        return f"0x{encoded_data.hex()}"
    
    def encode_list_data(self, owner: str, trusted: list, untrusted: list) -> str:
        """
        Encode trust list data in the OLI format.
        
        Args:
            owner (str): Owner name of the trust list
            trusted (dict): Dictionary of trusted entities
            untrusted (dict): Dictionary of untrusted entities
        Returns:
            str: Hex-encoded ABI data
        """
        # Convert list to JSON strings if needed
        if isinstance(trusted, list):
            trusted = json.dumps(trusted)
        if isinstance(untrusted, list):
            untrusted = json.dumps(untrusted)
        
        # ABI encode the data
        encoded_data = encode(['string', 'string', 'string'], [owner, trusted, untrusted])
        return f"0x{encoded_data.hex()}"
    
    def estimate_gas_limit(self, function, tx_params: dict, gas_limit: int) -> dict:
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
            if gas_limit == -1:
                # Estimate gas with a buffer (e.g., 10% more than the estimate)
                estimated_gas = function.estimate_gas(tx_params)
                tx_params["gas"] = int(estimated_gas * 1.1)  # Add 10% buffer
            else:
                tx_params["gas"] = gas_limit
        except Exception as e:
            tx_params["gas"] = 10000000  # Default fallback
        return tx_params
    
    def calculate_attestation_uid_v2(self, schema: str, recipient: str, attester: str, timestamp: int, data: str, expiration_time: int=0, revocable: bool=True, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", bump: int=0, salt: str=None) -> bytes:
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