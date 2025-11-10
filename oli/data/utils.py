import json
import pandas as pd
import networkx as nx

class UtilsData:
    def __init__(self, oli_client):
        """
        Initialize the UtilsData with an OLI client.

        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    # get confidence scores
    def get_confidence(self, attester: str, tag_id: str, chain_id: str) -> float:
        """
        Get the confidence score for a given attester, tag_id and chain_id from the trust table.

        Args:
            attester (str): Attester address
            tag_id (str): Tag ID
            chain_id (str): Chain ID
        
        Returns:
            float: Confidence score or -1 if no score was able to be assigned
        """
        # raise ValueError if trust table is empty
        if self.oli.trust.trust_table == {}:
            raise ValueError("Trust table is empty. Please use 'oli.set_trust_node(source_address)' function to set the source node, which will compute your trust table.")

        # Checksum the attester address
        attester = attester.lower()
        
        # Iterate through self.oli.trust.trust_table in order (is sorted by confidence)
        for (t_attester, t_tag, t_chain), confidence in self.oli.trust.trust_table.items():
            # Check if this entry matches (with wildcard support)
            if (t_attester.lower() == attester and (t_tag == tag_id or t_tag == '*') and (t_chain == chain_id or t_chain == '*')):
                return confidence
        
        return -1