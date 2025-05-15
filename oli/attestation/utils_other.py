import json
from eth_abi.abi import encode

class DataEncoder:
    def __init__(self, oli_client):
        """
        Initialize the DataEncoder with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def encode_label_data(self, chain_id, tags_json):
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