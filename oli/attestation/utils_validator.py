class UtilsValidator:
    def __init__(self, oli_client):
        """
        Initialize the DataValidator with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
        self.allowed_prefixes = [
            'eip155:',  # Ethereum and EVM-compatible chains
            'solana:',  # Solana
            'tron:',    # TRON
            'stellar:', # Stellar
            'bip122:',  # Bitcoin
            'SN_MAIN'   # Starknet
        ]
        # URLs for helpful resources
        self.url_1_label_schema = "https://github.com/openlabelsinitiative/OLI/tree/main/1_label_schema"
        self.url_2_label_pool = "https://github.com/openlabelsinitiative/OLI/tree/main/2_label_pool"
        self.url_3_label_trust = "https://github.com/openlabelsinitiative/OLI/tree/main/3_label_trust"
        self.url_tag_definitions = "https://github.com/openlabelsinitiative/OLI/blob/main/1_label_schema/tags/tag_definitions.yml"
        self.url_caip2_format = "https://docs.portalhq.io/resources/chain-id-formatting"

    def fix_simple_tags_formatting(self, tags: dict) -> dict:
        """
        Fix basic formatting in the tags dictionary. This includes:
        - Ensuring all tag_ids are lowercase
        - Booling values are converted from strings to booleans
        - Removing leading/trailing whitespace from string values
        - Checksum address (string(42)) tags
        
        Args:
            tags (dict): Dictionary of tags
            
        Returns:
            dict: Formatted tags
        """
        # Convert tag_ids to lowercase
        tags = {k.lower(): v for k, v in tags.items()}

        # Strip whitespaces, then turn boolean values from strings to booleans
        for k, v in tags.items():
            if isinstance(v, str):
                tags[k] = v.strip()
                if tags[k] == 'true':
                    tags[k] = True
                elif tags[k] == 'false':
                    tags[k] = False
            elif isinstance(v, list):
                tags[k] = [i.strip() if isinstance(i, str) else i for i in v]

        # Checksum address tags
        for k, v in tags.items():
            if k in self.oli.tag_definitions and 'minLength' in self.oli.tag_definitions[k]['schema']:
                if self.oli.tag_definitions[k]['schema']['minLength'] == 42 and self.oli.tag_definitions[k]['schema']['maxLength'] == 42:
                    tags[k] = self.oli.w3.to_checksum_address(v)

        return tags

    def validate_label_correctness(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", auto_fix: bool=True) -> bool:
        """
        Validates if the label is compliant with the OLI Label Schema. See OLI Github documentation for more details: https://github.com/openlabelsinitiative/OLI/tree/main/1_label_schema
        
        Args:
            address (str): Address to check
            chain_id (str): Chain ID to check
            tags (dict): Tags to check
            ref_uid (str): Reference UID to check
            auto_fix (bool): If True, will attempt to fix the label automatically using the fix_simple_tags_formatting function
            
        Returns:
            bool: True if the label is correct, False otherwise
        """
        # basic checks
        self.validate_address(address)
        self.validate_chain_id(chain_id)
        self.validate_tags(tags, auto_fix=auto_fix)
        self.validate_ref_uid(ref_uid)
        return True

    def validate_trust_list_correctness(self, owner_name: str, attesters: list, attestations: list) -> bool:
        """
        Validates if the trust list is compliant with the OLI Label Trust definitions. See OLI Github documentation for more details: https://github.com/openlabelsinitiative/OLI/tree/main/3_label_trust

        Args:
            owner (str): Owner name of the trust list
            attesters (list): List of attester information with confidence scores and optional filters
            attestations (list): List of attestation information with confidence scores

        Returns:
            bool: True if the trust list is correct, False otherwise
        """
        if owner_name.isascii() != True:
            print(owner_name)
            raise ValueError("Owner name must only contain ASCII characters")
        elif len(owner_name) < 3 or len(owner_name) > 100:
            print(owner_name)
            raise ValueError("Owner name must be between 3 and 100 characters long")
        self.validate_attesters_list(attesters)
        self.validate_attestations_list(attestations)
        return True

    def validate_chain_id(self, chain_id: str) -> bool:
        """
        Validates if chain_id for a label is in CAIP-2 format.
        
        Args:
            chain_id (str): Chain ID to check
            
        Returns:
            bool: True if correct, False otherwise
        """
        # Check if the chain_id starts with any of the allowed prefixes
        for prefix in self.allowed_prefixes:
            if chain_id.startswith(prefix):
                # For eip155, further validate that the rest is a number or 'any'
                if prefix == 'eip155:':
                    rest = chain_id[len(prefix):]
                    if rest.isdigit():
                        return True
                    elif rest == 'any':
                        print("Please ensure the label is accurate and consistent across all EVM chains before setting chain_id = 'eip155:any'.")
                        return True
                    else:
                        print(f"Invalid eip155 chain_id format: {chain_id}")
                        raise ValueError("For eip155 chains, format must be 'eip155:' followed by a number or 'any'")
                return True
        
        # If we get here, the chain_id didn't match any allowed format
        print(f"Unsupported chain ID format: {chain_id}")
        raise ValueError(f"Chain ID must be in CAIP-2 format (e.g., Base -> 'eip155:8453'), see this guide on CAIP-2: {self.url_caip2_format}")

    def validate_address(self, address: str) -> bool:
        """
        Validates if address is a valid Ethereum address.
        
        Args:
            address (str): Address to check
            
        Returns:
            bool: True if correct, False otherwise
        """
        if self.oli.w3.is_address(address):
            return True
        else:
            print(address)
            raise ValueError("Address must be a valid Ethereum address in hex format")
        
    def validate_tags(self, tags: dict, auto_fix: bool=False) -> bool:
        """
        Check if tags are in the correct format.
        
        Args:
            tags (dict): Tags to check
            
        Returns:
            bool: True if correct, False otherwise
        """
        # Check if tags is a dictionary
        if isinstance(tags, dict):
            if auto_fix:
                tags = self.fix_simple_tags_formatting(tags)
            else:
                pass
        else:
            print(tags)
            raise ValueError(f"Tags must be a dictionary with OLI compliant tags (e.g., {{'contract_name': 'example', 'is_eoa': True}}). See for example: {self.url_1_label_schema}")
        
        # Check each tag_id in the dictionary # TODO: redo this with tag_definitions 2.0 and schema, should be more efficient
        for tag_id in tags.keys():
            
            # Check if the tag_id is in the official OLI tag list
            if tag_id not in self.oli.tag_ids:
                print(f"WARNING: Tag tag_id '{tag_id}' is not an official OLI tag. Please check 'oli.tag_definitions' or {self.url_tag_definitions}.")
            
            # Check if the tag_id is in the correct format. So far implemented [boolean, string, integer, list, float, string(42), string(66), date (YYYY-MM-DD HH:MM:SS)]
            else:
                if self.oli.tag_definitions[tag_id]['schema']['type'] == 'boolean' and not isinstance(tags[tag_id], bool):
                    print(f"WARNING: Tag value for {tag_id} must be a boolean (True/False).")
                elif self.oli.tag_definitions[tag_id]['schema']['type'] == 'string' and not isinstance(tags[tag_id], str):
                    print(f"WARNING: Tag value for {tag_id} must be a string.")
                elif self.oli.tag_definitions[tag_id]['schema']['type'] == 'integer' and not isinstance(tags[tag_id], int):
                    print(f"WARNING: Tag value for {tag_id} must be an integer.")
                elif self.oli.tag_definitions[tag_id]['schema']['type'] == 'float' and not isinstance(tags[tag_id], float):
                    print(f"WARNING: Tag value for {tag_id} must be a float.")
                elif self.oli.tag_definitions[tag_id]['schema']['type'] == 'array' and not isinstance(tags[tag_id], list):
                    print(f"WARNING: Tag value for {tag_id} must be an array.")
                elif (
                        self.oli.tag_definitions[tag_id]['schema']['type'] == 'string' and 
                        self.oli.tag_definitions[tag_id]['schema'].get('minLength') == 42 and 
                        self.oli.tag_definitions[tag_id]['schema'].get('maxLength') == 42 and 
                        not self.oli.w3.is_address(tags[tag_id])
                    ):
                    print(f"WARNING: Tag value for {tag_id} must be a valid Ethereum address string with '0x'.")
                elif (
                        self.oli.tag_definitions[tag_id]['schema']['type'] == 'string' and 
                        self.oli.tag_definitions[tag_id]['schema'].get('minLength') == 66 and 
                        self.oli.tag_definitions[tag_id]['schema'].get('maxLength') == 66 and 
                        not (len(tags[tag_id]) == 66 and tags[tag_id].startswith('0x'))
                    ):
                    print(f"WARNING: Tag value for {tag_id} must be a valid hex string with '0x' prefix and 64 hex characters (66 characters total).")
                elif (
                        self.oli.tag_definitions[tag_id]['schema']['type'] == 'string' and 
                        self.oli.tag_definitions[tag_id]['schema'].get('format') == 'date-time' and 
                        not isinstance(tags[tag_id], str)
                    ):
                    print(f"WARNING: Tag value for {tag_id} must be a string in date-time format (e.g., '2023-12-31 23:59:59').")

            # Check if the value is in the value set
            if tag_id in self.oli.tag_value_sets:
                # single value
                if tags[tag_id] not in self.oli.tag_value_sets[tag_id] and not isinstance(tags[tag_id], list):
                    print(f"WARNING: Invalid tag value for {tag_id}: '{tags[tag_id]}'")
                    if len(self.oli.tag_value_sets[tag_id]) < 100:
                        print(f"Please use one of the following values for {tag_id}: {self.oli.tag_value_sets[tag_id]}")
                    else:
                        print(f"Please use a valid value from the predefined value_set for {tag_id}: {self.oli.tag_definitions[tag_id]['value_set']}")
                # list of values
                elif tags[tag_id] not in self.oli.tag_value_sets[tag_id] and isinstance(tags[tag_id], list):
                    for i in tags[tag_id]:
                        if i not in self.oli.tag_value_sets[tag_id]:
                            print(f"WARNING: Invalid tag value for {tag_id}: {i}")
                            if len(self.oli.tag_value_sets[tag_id]) < 100:
                                print(f"Please use a list of values from the predefined value_set for {tag_id}: {self.oli.tag_value_sets[tag_id]}")
                            else:
                                print(f"Please use a list of values from the predefined value_set for {tag_id}: {self.oli.tag_definitions[tag_id]['value_set']}")

    def validate_ref_uid(self, ref_uid: str) -> bool:
        """
        Validates if ref_uid is a valid UID.
        
        Args:
            ref_uid (str): Reference UID to check
            
        Returns:
            bool: True if correct, throws error otherwise
        """
        if ref_uid.startswith('0x') and len(ref_uid) == 66:
            return True
        else:
            print(ref_uid)
            raise ValueError("Ref_uid must be a valid UID in hex format")

    def validate_attesters_list(self, attesters: list) -> bool:
        """
        Validates if the attester list is in the correct format.

        Args:
            attesters (list): Attester list to check

        Returns:
            bool: True if correct, throws error otherwise
        """
        if not isinstance(attesters, list):
            raise ValueError("Attesters list must be a list.")

        for item in attesters:
            # Validate attester
            if 'address' in item:
                # check attester address
                self.validate_address(item['address'])
                # Check attester item
                self.validate_attester_item(item)
            else:
                print(item)
                raise ValueError(f"Each attester entry must have an 'address' key. See for example: {self.url_3_label_trust}")

        return True

    def validate_attestations_list(self, attestations: list) -> bool:
        """
        Validates if the attestations list is in the correct format.

        Args:
            untrusted (list): Untrusted list to check

        Returns:
            bool: True if correct, throws error otherwise
        """
        if not isinstance(attestations, list):
            raise ValueError("Attestations list must be a list.")

        for item in attestations:
            # Validate attestation
            if 'uid' in item:
                # check attestation UID
                self.validate_ref_uid(item['uid'])
                # check attestation item
                self.validate_attestation_item(item)
            else:
                print(item)
                raise ValueError(f"Each attestation entry must have an 'uid' key. See for example: {self.url_3_label_trust}")

        return True

    def validate_attester_item(self, item: dict) -> bool:
        """
        Validates if an attester item is in the correct format.
        
        Args:
            item (dict): Attester item to check

        Returns:
            bool: True if valid, throws error otherwise
        """
        # Check if confidence key is present
        if 'confidence' in item:
            if 'filters' in item:
                # if 'confidence' is assigned to an attester, then specific confidence scores based on 'filters' are not allowed
                print(item)
                raise ValueError(f"If a 'confidence' key is assigned to an attester, specific confidence scores based on 'filters' are not allowed. Please remove 'filters'. See for example: {self.url_3_label_trust}")
            elif item['confidence'] < 0 or item['confidence'] > 1:
                print(item)
                raise ValueError("'confidence' scores must be between 0 and 1")
        elif 'filters' in item:
            # make sure tag_id or chain_id is present in each entry in filters
            if isinstance(item['filters'], list):
                for tag in item['filters']:
                    if 'tag_id' not in tag and 'chain_id' not in tag:
                        print(item['filters'])
                        raise ValueError(f"Each filter must have a at least a key for 'tag_id' or 'chain_id'. See for example: {self.url_3_label_trust}")
                    elif 'confidence' not in tag:
                        print(item['filters'])
                        raise ValueError(f"Each filter must have a key called 'confidence'. See for example: {self.url_3_label_trust}")
                    elif tag['confidence'] < 0 or tag['confidence'] > 1:
                        print(item['filters'])
                        raise ValueError("Each 'confidence' score must be between 0 and 1")
            else:
                print(item['filters'])
                raise ValueError(f"'filters' must be a list of dictionaries with 'tag_id' or 'chain_id' filters and a 'confidence' score between 0 and 1. See for example: {self.url_3_label_trust}")
        else:
            print(item)
            raise ValueError(f"Each attester entry must have either have a 'confidence' or 'filters' key. See for example: {self.url_3_label_trust}")
        return True

    def validate_attestation_item(self, item: dict) -> bool:
        """
        Validates if an attestation item is in the correct format.

        Args:
            item (dict): Attestation item to check

        Returns:
            bool: True if valid, throws error otherwise
        """
        if 'confidence' not in item:
            print(item)
            raise ValueError(f"Each attestation entry with a 'uid' key must also have a 'confidence' key. See for example: {self.url_3_label_trust}")
        elif item['confidence'] < 0 or item['confidence'] > 1:
            print(item)
            raise ValueError(f"Confidence must be between 0 and 1.")
        return True