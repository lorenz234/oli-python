import pandas as pd

class UtilsData:
    def __init__(self, oli_client):
        """
        Initialize the UtilsData with an OLI client.

        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client

    def filter_labels(self, df, attester=None, chain_id=None, tag_id=None):
        if attester and attester != '*':
            df = df[df['attester'] == attester]
        if chain_id and chain_id != '*':
            df = df[df['chain_id'] == chain_id]
        if tag_id and tag_id != '*':
            df = df[df['tag_id'] == tag_id]
        return df

    def filter_labels_by_trust_list(self, df: pd.DataFrame, trusted: list, untrusted: list, min_score: int, show_revoked: bool) -> pd.DataFrame:
        """
        Filter labels based on a trust list.
        
        Args:
            df (pd.DataFrame): DataFrame of labels to filter
            trusted (list): List of trusted rules
            untrusted (list): List of untrusted rules
            threshold (int): Minimum score threshold to keep a label
        
        Returns:
            pd.DataFrame: Filtered DataFrame of labels
        """
        df['score'] = 0

        # Apply trusted rules
        for rule in trusted:
            # Apply attestation scores
            if 'attestation' in rule:
                df.loc[df['id'] == rule['attestation'], 'score'].apply(lambda x: max(x, rule['score']))
            elif 'attester' in rule:
                # Apply attester base score
                if 'score' in list(rule):
                    df.loc[self.filter_labels(df, attester=rule['attester']).index, 'score'] = df.loc[self.filter_labels(df, attester=rule['attester']).index, 'score'].apply(lambda x: max(x, rule['score']))
                # Apply filter specific scores
                if 'filters' in list(rule):
                    for filter in rule['filters']:
                        df.loc[self.filter_labels(df, attester=filter.get('attester'), chain_id=filter.get('chain_id'), tag_id=filter.get('tag_id')).index, 'score'] = df.loc[self.filter_labels(df, attester=filter.get('attester'), chain_id=filter.get('chain_id'), tag_id=filter.get('tag_id')).index, 'score'].apply(lambda x: max(x, filter['score']))

        # Apply untrusted rules
        ### TODO

        # remove all rows below a certain score threshold & return
        df = df[df['score'] >= min_score]

        # remove revoked if not wanted
        if show_revoked is False:
            df = df[df['revoked'] == False]

        return df