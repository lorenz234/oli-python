import requests
import yaml

class DataFetcher:
    def __init__(self, oli_client):
        """
        Initialize the DataFetcher with an OLI client.
        
        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client
    
    def get_OLI_tags(self):
        """
        Get latest OLI tags from OLI Github repo.
        
        Returns:
            dict: Dictionary of official OLI tags
        """
        url = "https://raw.githubusercontent.com/openlabelsinitiative/OLI/refs/heads/main/1_label_schema/tags/tag_definitions.yml"
        response = requests.get(url)
        if response.status_code == 200:
            y = yaml.safe_load(response.text)
            y = {i['tag_id']: i for i in y['tags']}
            return y
        else:
            raise Exception(f"Failed to fetch OLI tags from Github: {response.status_code} - {response.text}")

    def get_OLI_value_sets(self) -> dict:
        """
        Get latest value sets for OLI tags.
        
        Returns:
            dict: Dictionary of value sets with tag_id as key
        """
        value_sets = {}

        # Extract value sets from tag definitions (must be a list)
        for tag_def in self.oli.tag_definitions.values():
            if 'schema' not in tag_def:
                continue
            
            schema = tag_def['schema']
            tag_id = tag_def['tag_id']
            value_set = None
            
            # Get enum from direct schema or array items
            if 'enum' in schema:
                value_set = schema['enum']
            elif (schema.get('type') == 'array' and 
                'items' in schema and 
                'enum' in schema['items']):
                value_set = schema['items']['enum']
            
            # Process and add to value_sets
            if value_set and isinstance(value_set, list):
                value_sets[tag_id] = [i.lower() if isinstance(i, str) else i for i in value_set]

        # value set for owner_project
        url = "https://api.growthepie.com/v1/labels/projects.json" 
        response = requests.get(url)
        if response.status_code == 200:
            y = yaml.safe_load(response.text)
            value_sets["owner_project"] = [i[0] for i in y['data']['data']]
            value_sets["owner_project"] = [i.lower() if isinstance(i, str) else i for i in value_sets["owner_project"]]
        else:
            raise Exception(f"Failed to fetch owner_project value set from grwothepie projects api: {response.status_code} - {response.text}")

        # value set for usage_category
        url = "https://raw.githubusercontent.com/openlabelsinitiative/OLI/refs/heads/main/1_label_schema/tags/valuesets/usage_category.yml"
        response = requests.get(url)
        if response.status_code == 200:
            y = yaml.safe_load(response.text)
            value_sets['usage_category'] = [i['category_id'] for i in y['categories']]
            value_sets['usage_category'] = [i.lower() if isinstance(i, str) else i for i in value_sets['usage_category']]
        else:
            raise Exception(f"Failed to fetch usage_category value set from OLI Github: {response.status_code} - {response.text}")

        return value_sets
    
    def get_full_raw_export_parquet(self, file_path: str="raw_labels.parquet") -> str:
        """
        Downloads the full raw export of all labels in the OLI Label Pool as a Parquet file.
        
        Args:
            file_path (str): Path where the file will be saved. Defaults to "raw_labels.parquet".
            
        Returns:
            str: Path to the downloaded Parquet file
        """
        url = "https://api.growthepie.com/v1/oli/labels_raw.parquet"
        
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded and saved: {file_path}")
            return file_path
        else:
            print(f"Failed to download {url}. Status code: {response.status_code}")
            return None

    def get_full_decoded_export_parquet(self, file_path: str="decoded_labels.parquet") -> str:
        """
        Downloads the full decoded export of all labels in the OLI Label Pool as a Parquet file.
        
        Args:
            file_path (str): Path where the file will be saved. Defaults to "decoded_labels.parquet".
            
        Returns:
            str: Path to the downloaded Parquet file
        """
        url = "https://api.growthepie.com/v1/oli/labels_decoded.parquet"
        
        response = requests.get(url, stream=True)
        if response.status_code == 200:
            with open(file_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded and saved: {file_path}")
            return file_path
        else:
            print(f"Failed to download {url}. Status code: {response.status_code}")
            return None