import requests

class GraphQLClient:
    def __init__(self, oli_client):
        """
        Initialize the GraphQLClient with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def graphql_query_attestations(self, address: str=None, attester: str=None, timeCreated: int=None, revocationTime: int=None) -> dict:
        """
        Queries attestations from the EAS GraphQL API based on the specified filters.
        
        Args:
            address (str, optional): Ethereum address of the labeled contract
            attester (str, optional): Ethereum address of the attester
            timeCreated (int, optional): Filter for attestations created after this timestamp
            revocationTime (int, optional): Filter for attestations with revocation time >= this timestamp
            
        Returns:
            dict: JSON response containing matching attestation data
        """
        query = """
            query Attestations($take: Int, $where: AttestationWhereInput, $orderBy: [AttestationOrderByWithRelationInput!]) {
                attestations(take: $take, where: $where, orderBy: $orderBy) {
                    attester
                    decodedDataJson
                    expirationTime
                    id
                    ipfsHash
                    isOffchain
                    recipient
                    refUID
                    revocable
                    revocationTime
                    revoked
                    time
                    timeCreated
                    txid
                }
            }
        """
            
        variables = {
            "where": {
                "schemaId": {
                    "equals": self.oli.oli_label_pool_schema
                }
            },
            "orderBy": [
                {
                "timeCreated": "desc"
                }
            ]
        }
        
        # Add address to where clause if not None
        if address is not None:
            variables["where"]["recipient"] = {"equals": address}

        # Add attester to where clause if not None
        if attester is not None:
            variables["where"]["attester"] = {"equals": attester}
        
        # Add timeCreated to where clause if not None, ensuring it's an int
        if timeCreated is not None:
            timeCreated = int(timeCreated)
            variables["where"]["timeCreated"] = {"gt": timeCreated}
        
        # Add revocationTime to where clause if not None, ensuring it's an int
        if revocationTime is not None:
            revocationTime = int(revocationTime)
            variables["where"]["revocationTime"] = {"gte": revocationTime}
        
        headers = {
            "Content-Type": "application/json"
        }
        
        response = requests.post(self.oli.graphql, json={"query": query, "variables": variables}, headers=headers)
        
        if response.status_code == 200:
            return response.json()
        else:
            raise Exception(f"GraphQL query failed with status code {response.status_code}: {response.text}")
