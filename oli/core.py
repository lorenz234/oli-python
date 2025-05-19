from web3 import Web3
import eth_account
import os
from eth_keys import keys
from requests import Response

from oli.attestation.utils_validator import UtilsValidator
from oli.attestation.utils_other import UtilsOther
from oli.attestation.onchain import OnchainAttestations
from oli.attestation.offchain import OffchainAttestations
from oli.data.fetcher import DataFetcher
from oli.data.graphql import GraphQLClient

class OLI:
    def __init__(self, private_key: str=None, is_production: bool=True, custom_rpc_url: str=None) -> None:
        """
        Initialize the OLI API client.
        
        Args:
            private_key (str): The private key to sign attestations
            is_production (bool): Whether to use production or testnet
            custom_rpc_url (str): Custom RPC URL to connect to Blockchain
        """
        print("Initializing OLI API client...")

        # Set network based on environment
        if is_production:
            self.rpc = "https://mainnet.base.org"
            self.graphql = "https://base.easscan.org/graphql"
            self.rpc_chain_number = 8453
            self.eas_api_url = "https://base.easscan.org/offchain/store"
            self.eas_address = "0x4200000000000000000000000000000000000021"  # EAS contract address on mainnet
        else:
            self.rpc = "https://sepolia.base.org"
            self.graphql = "https://base-sepolia.easscan.org/graphql"
            self.rpc_chain_number = 84532
            self.eas_api_url = "https://base-sepolia.easscan.org/offchain/store"
            self.eas_address = "0x4200000000000000000000000000000000000021"  # EAS contract address on testnet
        
        # Use provided RPC endpoint if specified
        if custom_rpc_url is not None:
            self.rpc = custom_rpc_url

        # Initialize Web3 and account
        self.w3 = Web3(Web3.HTTPProvider(self.rpc))
        if not self.w3.is_connected():
            raise Exception("Failed to connect to the Ethereum node")
        
        # Try to get private key from environment if not provided
        if private_key is None:
            private_key = os.environ.get('OLI_PRIVATE_KEY')
            if not private_key:
                print("WARNING: Private key not provided. Please set the OLI_PRIVATE_KEY environment variable in case you plan to submit labels.")
                print("WARNING: OLI client in read mode only.")
        
        self.private_key = private_key
        if self.private_key:
            # Convert the hex private key to the proper key object
            if private_key.startswith('0x'):
                private_key_bytes = private_key[2:]
            else:
                private_key_bytes = private_key
            # Create account from private key
            private_key_obj = keys.PrivateKey(bytes.fromhex(private_key_bytes))
            self.account = eth_account.Account.from_key(private_key_obj)
            self.address = self.account.address
        
        # Label Pool Schema for OLI
        self.oli_label_pool_schema = '0xb763e62d940bed6f527dd82418e146a904e62a297b8fa765c9b3e1f0bc6fdd68'
        
        # Load EAS ABI
        self.eas_abi = '[{"inputs": [],"stateMutability": "nonpayable","type": "constructor"},{"inputs": [],"name": "AccessDenied","type": "error"},{"inputs": [],"name": "AlreadyRevoked","type": "error"},{"inputs": [],"name": "AlreadyRevokedOffchain","type": "error"},{"inputs": [],"name": "AlreadyTimestamped","type": "error"},{"inputs": [],"name": "DeadlineExpired","type": "error"},{"inputs": [],"name": "InsufficientValue","type": "error"},{"inputs": [],"name": "InvalidAttestation","type": "error"},{"inputs": [],"name": "InvalidAttestations","type": "error"},{"inputs": [],"name": "InvalidExpirationTime","type": "error"},{"inputs": [],"name": "InvalidLength","type": "error"},{"inputs": [],"name": "InvalidNonce","type": "error"},{"inputs": [],"name": "InvalidOffset","type": "error"},{"inputs": [],"name": "InvalidRegistry","type": "error"},{"inputs": [],"name": "InvalidRevocation","type": "error"},{"inputs": [],"name": "InvalidRevocations","type": "error"},{"inputs": [],"name": "InvalidSchema","type": "error"},{"inputs": [],"name": "InvalidSignature","type": "error"},{"inputs": [],"name": "InvalidVerifier","type": "error"},{"inputs": [],"name": "Irrevocable","type": "error"},{"inputs": [],"name": "NotFound","type": "error"},{"inputs": [],"name": "NotPayable","type": "error"},{"inputs": [],"name": "WrongSchema","type": "error"},{"anonymous": false,"inputs": [{"indexed": true,"internalType": "address","name": "recipient","type": "address"},{"indexed": true,"internalType": "address","name": "attester","type": "address"},{"indexed": false,"internalType": "bytes32","name": "uid","type": "bytes32"},{"indexed": true,"internalType": "bytes32","name": "schemaUID","type": "bytes32"}],"name": "Attested","type": "event"},{"anonymous": false,"inputs": [{"indexed": false,"internalType": "uint256","name": "oldNonce","type": "uint256"},{"indexed": false,"internalType": "uint256","name": "newNonce","type": "uint256"}],"name": "NonceIncreased","type": "event"},{"anonymous": false,"inputs": [{"indexed": true,"internalType": "address","name": "recipient","type": "address"},{"indexed": true,"internalType": "address","name": "attester","type": "address"},{"indexed": false,"internalType": "bytes32","name": "uid","type": "bytes32"},{"indexed": true,"internalType": "bytes32","name": "schemaUID","type": "bytes32"}],"name": "Revoked","type": "event"},{"anonymous": false,"inputs": [{"indexed": true,"internalType": "address","name": "revoker","type": "address"},{"indexed": true,"internalType": "bytes32","name": "data","type": "bytes32"},{"indexed": true,"internalType": "uint64","name": "timestamp","type": "uint64"}],"name": "RevokedOffchain","type": "event"},{"anonymous": false,"inputs": [{"indexed": true,"internalType": "bytes32","name": "data","type": "bytes32"},{"indexed": true,"internalType": "uint64","name": "timestamp","type": "uint64"}],"name": "Timestamped","type": "event"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "address","name": "recipient","type": "address"},{"internalType": "uint64","name": "expirationTime","type": "uint64"},{"internalType": "bool","name": "revocable","type": "bool"},{"internalType": "bytes32","name": "refUID","type": "bytes32"},{"internalType": "bytes","name": "data","type": "bytes"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct AttestationRequestData","name": "data","type": "tuple"}],"internalType": "struct AttestationRequest","name": "request","type": "tuple"}],"name": "attest","outputs": [{"internalType": "bytes32","name": "","type": "bytes32"}],"stateMutability": "payable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "address","name": "recipient","type": "address"},{"internalType": "uint64","name": "expirationTime","type": "uint64"},{"internalType": "bool","name": "revocable","type": "bool"},{"internalType": "bytes32","name": "refUID","type": "bytes32"},{"internalType": "bytes","name": "data","type": "bytes"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct AttestationRequestData","name": "data","type": "tuple"},{"components": [{"internalType": "uint8","name": "v","type": "uint8"},{"internalType": "bytes32","name": "r","type": "bytes32"},{"internalType": "bytes32","name": "s","type": "bytes32"}],"internalType": "struct Signature","name": "signature","type": "tuple"},{"internalType": "address","name": "attester","type": "address"},{"internalType": "uint64","name": "deadline","type": "uint64"}],"internalType": "struct DelegatedAttestationRequest","name": "delegatedRequest","type": "tuple"}],"name": "attestByDelegation","outputs": [{"internalType": "bytes32","name": "","type": "bytes32"}],"stateMutability": "payable","type": "function"},{"inputs": [],"name": "getAttestTypeHash","outputs": [{"internalType": "bytes32","name": "","type": "bytes32"}],"stateMutability": "pure","type": "function"},{"inputs": [{"internalType": "bytes32","name": "uid","type": "bytes32"}],"name": "getAttestation","outputs": [{"components": [{"internalType": "bytes32","name": "uid","type": "bytes32"},{"internalType": "bytes32","name": "schema","type": "bytes32"},{"internalType": "uint64","name": "time","type": "uint64"},{"internalType": "uint64","name": "expirationTime","type": "uint64"},{"internalType": "uint64","name": "revocationTime","type": "uint64"},{"internalType": "bytes32","name": "refUID","type": "bytes32"},{"internalType": "address","name": "recipient","type": "address"},{"internalType": "address","name": "attester","type": "address"},{"internalType": "bool","name": "revocable","type": "bool"},{"internalType": "bytes","name": "data","type": "bytes"}],"internalType": "struct Attestation","name": "","type": "tuple"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "getDomainSeparator","outputs": [{"internalType": "bytes32","name": "","type": "bytes32"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "getName","outputs": [{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "account","type": "address"}],"name": "getNonce","outputs": [{"internalType": "uint256","name": "","type": "uint256"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "address","name": "revoker","type": "address"},{"internalType": "bytes32","name": "data","type": "bytes32"}],"name": "getRevokeOffchain","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "view","type": "function"},{"inputs": [],"name": "getRevokeTypeHash","outputs": [{"internalType": "bytes32","name": "","type": "bytes32"}],"stateMutability": "pure","type": "function"},{"inputs": [],"name": "getSchemaRegistry","outputs": [{"internalType": "contract ISchemaRegistry","name": "","type": "address"}],"stateMutability": "pure","type": "function"},{"inputs": [{"internalType": "bytes32","name": "data","type": "bytes32"}],"name": "getTimestamp","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "view","type": "function"},{"inputs": [{"internalType": "uint256","name": "newNonce","type": "uint256"}],"name": "increaseNonce","outputs": [],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "bytes32","name": "uid","type": "bytes32"}],"name": "isAttestationValid","outputs": [{"internalType": "bool","name": "","type": "bool"}],"stateMutability": "view","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "address","name": "recipient","type": "address"},{"internalType": "uint64","name": "expirationTime","type": "uint64"},{"internalType": "bool","name": "revocable","type": "bool"},{"internalType": "bytes32","name": "refUID","type": "bytes32"},{"internalType": "bytes","name": "data","type": "bytes"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct AttestationRequestData[]","name": "data","type": "tuple[]"}],"internalType": "struct MultiAttestationRequest[]","name": "multiRequests","type": "tuple[]"}],"name": "multiAttest","outputs": [{"internalType": "bytes32[]","name": "","type": "bytes32[]"}],"stateMutability": "payable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "address","name": "recipient","type": "address"},{"internalType": "uint64","name": "expirationTime","type": "uint64"},{"internalType": "bool","name": "revocable","type": "bool"},{"internalType": "bytes32","name": "refUID","type": "bytes32"},{"internalType": "bytes","name": "data","type": "bytes"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct AttestationRequestData[]","name": "data","type": "tuple[]"},{"components": [{"internalType": "uint8","name": "v","type": "uint8"},{"internalType": "bytes32","name": "r","type": "bytes32"},{"internalType": "bytes32","name": "s","type": "bytes32"}],"internalType": "struct Signature[]","name": "signatures","type": "tuple[]"},{"internalType": "address","name": "attester","type": "address"},{"internalType": "uint64","name": "deadline","type": "uint64"}],"internalType": "struct MultiDelegatedAttestationRequest[]","name": "multiDelegatedRequests","type": "tuple[]"}],"name": "multiAttestByDelegation","outputs": [{"internalType": "bytes32[]","name": "","type": "bytes32[]"}],"stateMutability": "payable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "bytes32","name": "uid","type": "bytes32"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct RevocationRequestData[]","name": "data","type": "tuple[]"}],"internalType": "struct MultiRevocationRequest[]","name": "multiRequests","type": "tuple[]"}],"name": "multiRevoke","outputs": [],"stateMutability": "payable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "bytes32","name": "uid","type": "bytes32"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct RevocationRequestData[]","name": "data","type": "tuple[]"},{"components": [{"internalType": "uint8","name": "v","type": "uint8"},{"internalType": "bytes32","name": "r","type": "bytes32"},{"internalType": "bytes32","name": "s","type": "bytes32"}],"internalType": "struct Signature[]","name": "signatures","type": "tuple[]"},{"internalType": "address","name": "revoker","type": "address"},{"internalType": "uint64","name": "deadline","type": "uint64"}],"internalType": "struct MultiDelegatedRevocationRequest[]","name": "multiDelegatedRequests","type": "tuple[]"}],"name": "multiRevokeByDelegation","outputs": [],"stateMutability": "payable","type": "function"},{"inputs": [{"internalType": "bytes32[]","name": "data","type": "bytes32[]"}],"name": "multiRevokeOffchain","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "bytes32[]","name": "data","type": "bytes32[]"}],"name": "multiTimestamp","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "bytes32","name": "uid","type": "bytes32"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct RevocationRequestData","name": "data","type": "tuple"}],"internalType": "struct RevocationRequest","name": "request","type": "tuple"}],"name": "revoke","outputs": [],"stateMutability": "payable","type": "function"},{"inputs": [{"components": [{"internalType": "bytes32","name": "schema","type": "bytes32"},{"components": [{"internalType": "bytes32","name": "uid","type": "bytes32"},{"internalType": "uint256","name": "value","type": "uint256"}],"internalType": "struct RevocationRequestData","name": "data","type": "tuple"},{"components": [{"internalType": "uint8","name": "v","type": "uint8"},{"internalType": "bytes32","name": "r","type": "bytes32"},{"internalType": "bytes32","name": "s","type": "bytes32"}],"internalType": "struct Signature","name": "signature","type": "tuple"},{"internalType": "address","name": "revoker","type": "address"},{"internalType": "uint64","name": "deadline","type": "uint64"}],"internalType": "struct DelegatedRevocationRequest","name": "delegatedRequest","type": "tuple"}],"name": "revokeByDelegation","outputs": [],"stateMutability": "payable","type": "function"},{"inputs": [{"internalType": "bytes32","name": "data","type": "bytes32"}],"name": "revokeOffchain","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "nonpayable","type": "function"},{"inputs": [{"internalType": "bytes32","name": "data","type": "bytes32"}],"name": "timestamp","outputs": [{"internalType": "uint64","name": "","type": "uint64"}],"stateMutability": "nonpayable","type": "function"},{"inputs": [],"name": "version","outputs": [{"internalType": "string","name": "","type": "string"}],"stateMutability": "view","type": "function"}]'

        # Initialize EAS contract
        self.eas = self.w3.eth.contract(address=self.eas_address, abi=self.eas_abi)
    
        # Initialize components
        self.data_fetcher = DataFetcher(self)
        self.tag_definitions = self.data_fetcher.get_OLI_tags()
        self.tag_ids = list(self.tag_definitions.keys())
        self.tag_value_sets = self.data_fetcher.get_OLI_value_sets()
        
        # Initialize validator
        self.validator = UtilsValidator(self)
        
        # Initialize other utilities
        self.utils_other = UtilsOther(self)
        
        # Initialize onchain and offchain attestations
        self.onchain = OnchainAttestations(self)
        self.offchain = OffchainAttestations(self)
        
        # Initialize GraphQL client
        self.graphql_client = GraphQLClient(self)

        print("...OLI client successfully initialized.")
    
    # Expose onchain attestation methods
    def submit_onchain_label(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", gas_limit: int=0) -> tuple[str, str]:
        return self.onchain.submit_onchain_label(address, chain_id, tags, ref_uid, gas_limit)
    
    def submit_multi_onchain_labels(self, labels: list, gas_limit: int=0) -> tuple[str, list]:
        return self.onchain.submit_multi_onchain_labels(labels, gas_limit)
    
    # Expose offchain attestation methods
    def submit_offchain_label(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", retry: int=4) -> Response:
        return self.offchain.submit_offchain_label(address, chain_id, tags, ref_uid, retry)
    
    # Expose revocation methods
    def revoke_attestation(self, uid_hex: str, onchain: bool, gas_limit: int=200000) -> str:
        if onchain:
            return self.onchain.revoke_attestation(uid_hex, gas_limit)
        else:
            return self.offchain.revoke_attestation(uid_hex, gas_limit)
    
    def multi_revoke_attestations(self, uids: str, onchain: bool, gas_limit: int=10000000) -> str:
        if onchain:
            return self.onchain.multi_revoke_attestations(uids, gas_limit)
        else:
            return self.offchain.multi_revoke_attestations(uids, gas_limit)
    
    # Expose query methods
    def graphql_query_attestations(self, address: str=None, attester: str=None, timeCreated: int=None, revocationTime: int=None) -> dict:
        return self.graphql_client.graphql_query_attestations(address, attester, timeCreated, revocationTime)
    
    def get_full_raw_export_parquet(self, file_path: str="raw_labels.parquet") -> str:
        return self.data_fetcher.get_full_raw_export_parquet(file_path)
    
    def get_full_decoded_export_parquet(self, file_path: str="decoded_labels.parquet") -> str:
        return self.data_fetcher.get_full_decoded_export_parquet(file_path)
    
    # Expose validation methods
    def validate_label_correctness(self, address: str, chain_id: str, tags: dict, ref_uid: str="0x0000000000000000000000000000000000000000000000000000000000000000", auto_fix: bool=True) -> bool:
        return self.validator.validate_label_correctness(address, chain_id, tags, ref_uid, auto_fix)
    
    def fix_simple_tags_formatting(self, tags: dict) -> dict:
        return self.validator.fix_simple_tags_formatting(tags)