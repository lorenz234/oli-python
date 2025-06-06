import requests
import json

class GraphQLClient:
    def __init__(self, oli_client):
        """
        Initialize the GraphQLClient with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def graphql_query_attestations(self, address: str=None, attester: str=None, timeCreated: int=None, revocationTime: int=None, take: int=None, id: str=None, expand_json: bool=True) -> dict:
        """
        Queries attestations from the EAS GraphQL API based on the specified filters.
        
        Args:
            address (str, optional): Ethereum address of the labeled contract
            attester (str, optional): Ethereum address of the attester
            timeCreated (int, optional): Filter for attestations created after this timestamp
            revocationTime (int, optional): Filter for attestations with revocation time >= this timestamp
            take (int, optional): Maximum number of attestations to return
            id (str, optional): Specific attestation ID to filter by
            expand_json (bool, default: True): Whether to expand decodedDataJson fields in the response
            
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
        
        # Add take to variables if not None
        if take is not None:
            variables["take"] = int(take)
        
        # Add id to where clause if not None
        if id is not None:
            variables["where"]["id"] = {"equals": id}
        
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
            if expand_json:
                # Expand decodedDataJson fields in the response
                return self.graphql_expand_decoded_data_json(response.json())
            else:
                # Return raw response if no expansion is wanted
                return response.json()
        else:
            raise Exception(f"GraphQL query failed with status code {response.status_code}: {response.text}")
        
    def graphql_expand_decoded_data_json(self, attestations_data: dict) -> list:
        """
        Expand decodedDataJson fields in attestations data into separate columns.
        
        Args:
            attestations_data (dict): GraphQL response from oli.graphql_query_attestations()
        
        Returns:
            list: List of dictionaries with expanded decodedDataJson fields
        """
        expanded_data = []
        
        for row in attestations_data['data']['attestations']:
            # Start with the original row data
            expanded_row = row.copy()
            
            # Check if decodedDataJson exists and is not None
            if 'decodedDataJson' in row and row['decodedDataJson']:
                try:
                    # Parse the JSON string
                    if isinstance(row['decodedDataJson'], str):
                        decoded_data = json.loads(row['decodedDataJson'])
                    else:
                        decoded_data = row['decodedDataJson']
                    
                    # Extract each field from the decoded data
                    for item in decoded_data:
                        field_name = item['name']
                        
                        # Extract the actual value from the nested structure
                        if 'value' in item and 'value' in item['value']:
                            value = item['value']['value']
                            
                            # Handle BigNumber hex values
                            if isinstance(value, dict) and value.get('type') == 'BigNumber':
                                expanded_row[field_name] = int(value['hex'], 16)
                            # Handle empty arrays or objects
                            elif isinstance(value, (list, dict)) and not value:
                                expanded_row[field_name] = value
                            else:
                                expanded_row[field_name] = value
                        else:
                            expanded_row[field_name] = None
                            
                except (json.JSONDecodeError, KeyError, TypeError) as e:
                    # If parsing fails, keep original row and add error info
                    expanded_row['_parsing_error'] = str(e)
            
            expanded_data.append(expanded_row)
        
        return {'data': {'attestations': expanded_data}}
