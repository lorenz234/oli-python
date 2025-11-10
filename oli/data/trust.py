import networkx as nx

class UtilsTrust:
    def __init__(self, oli_client):
        """
        Initialize the UtilsTrust with an OLI client.

        Args:
            oli_client: The OLI client instance
        """
        self.oli = oli_client

        # init trust variables
        try:
            self.raw_trust_lists = self.get_trust_lists_from_api()
            self.TrustGraph = self.build_trust_graph(self.raw_trust_lists)
            self.trust_table = self.compute_trust_table(self.TrustGraph, source_node=self.oli.source_address)
        except:
            self.raw_trust_lists = {}
            self.trust_table = {}
            self.TrustGraph = nx.MultiDiGraph()

    # computes the trust table for a given source node
    def compute_trust_table(self, TrustGraph: nx.MultiDiGraph, source_node: str=None) -> dict:
        """
        Compute the full trust table for the source node in the trust graph.
        """
        # get all tag_id & chain_id topics
        tags_id = set()
        chain_ids = set()
        for _, _, edge_data in TrustGraph.edges(data=True):
            tags_id.add(edge_data['topics']['tag_id'])
            chain_ids.add(edge_data['topics']['chain_id'])

        # resulting trust table
        trust_table = {}

        # Compute trust for all combinations
        for tag_id_val in tags_id:
            for chain_id_val in chain_ids:
                query = {'tag_id': tag_id_val, 'chain_id': chain_id_val}
                scores = self._dijkstra_trust(TrustGraph, source_node.lower(), query)
                for target_node, score in scores.items():
                    #key = (source_node, target_node, tag_id_val, chain_id_val)
                    key = (target_node, tag_id_val, chain_id_val)
                    trust_table[key] = score

        # Remove redundant entries
        trust_table = self._remove_redundant_entries(trust_table)

        # Keep entries ordered by highest confidence first for predictable consumption
        trust_table = dict(sorted(trust_table.items(), key=lambda item: item[1], reverse=True))

        return trust_table

    # Build trust graph from raw trust lists
    def build_trust_graph(self, raw_trust_lists) -> bool:
        """
        Build the trust graph (TrustGraph) based on all trust lists stored in self.raw_trust_lists.
        """

        # Keeps track of all unique nodes in the trust graph (trust list attesters + attestation attesters)
        nodes = []

        # Topics
        edges = []
        for address, tl in raw_trust_lists.items():
            if address.lower() not in nodes:
                nodes.append(address.lower())
            for t in tl['attesters']:
                if 'filters' not in t:
                    # Add trusted attesters (who have no filters) e.g. {'attester': '0xC139d50144Ee873c8577d682628E045dECe6040E', 'confidence': 0.8}
                    edges += [(address.lower(), t['address'].lower(), float(t['confidence']), {'chain_id': '*', 'tag_id': '*'})]
                    if t['address'].lower() not in nodes:
                        nodes.append(t['address'].lower())

                elif 'filters' in t:
                    # Add trusted attesters (with filters) e.g. {'attester': '0x10dBAc4d35f4aD47E85f70c74e4449c632EC4047', 'filters': [{'tag_id': 'is_contract', 'chain_id': 'eip155:48900', 'confidence': 0.9}
                    for f in t['filters']:
                        edges += [(address.lower(), t['address'].lower(), float(f['confidence']), {'chain_id': f.get('chain_id', '*'), 'tag_id': f.get('tag_id', '*')})]
                        if t['address'].lower() not in nodes:
                            nodes.append(t['address'].lower())

        # Create multi directed graph
        TrustGraph = nx.MultiDiGraph()
        TrustGraph.add_nodes_from(nodes)

        print(f"Building trust graph based on {len(raw_trust_lists)} trust list(s), {len(nodes)} node(s) and {len(edges)} edge(s).")

        # Add edges with attributes
        for src, dst, trust, topics in edges:
            TrustGraph.add_edge(src, dst, trust=trust, topics=topics)

        return TrustGraph

    def get_trust_lists_from_api(self) -> dict:
        """
        Fetch trust lists (that are valid) from the OLI API and return them as a dictionary to be saved as 'oli.trust.raw_trust_lists'.
        """
        trust_lists = {}
        for tl in self.oli.api.get_trust_lists(order='asc')['trust_lists']:
            if tl['revoked'] == False and self.oli.validate_trust_list(tl['owner_name'], tl['attesters'], tl['attestations']):
                trust_lists[tl['attester']] = {
                    'owner_name': tl['owner_name'],
                    'attesters': tl['attesters'],
                    'attestations': tl['attestations']
                }
        return trust_lists

    def add_trust_list(self, owner_name: str, attesters: list, attestations: list, attester_address: str) -> bool:
        """
        Add (or overwrite) a trust list to the OLI trust_list variable and rebuild the trust graph.

        Args:
            owner_name (str): The name of the owner of the trust list
            attesters (list): List of attesters in the trust list
            attestations (list): List of attestations in the trust list
            attester_address (str): The address of the attester providing the trust list

        Returns:
            bool: True if the trust list was added successfully
        """
        try:
            success = self.oli.validate_trust_list(owner_name, attesters, attestations)
            if success:
                self.raw_trust_lists[attester_address] = {
                    'owner_name': owner_name,
                    'attesters': attesters,
                    'attestations': attestations
                }
                self.TrustGraph = self.build_trust_graph(self.raw_trust_lists)
        except:
            raise ValueError("Trust list validation failed or 'attester_address' invalid. No trust list added to TrustGraph. See validation errors above.")
        
        return True

    # Dijkstra with no specificity logic
    def _dijkstra_trust(self, G: nx.MultiDiGraph, source: str, query_topics: dict) -> dict:
        trust_scores = {}
        visited = set()
        pq = [(-1.0, source)]

        while pq:
            neg_trust, node = min(pq, key=lambda x: x[0])
            pq.remove((neg_trust, node))
            
            if node in visited:
                continue
            visited.add(node)
            
            current_trust = -neg_trust
            
            for neighbor in G.successors(node):
                for key, edge_data in G[node][neighbor].items():
                    if self._topics_match(edge_data['topics'], query_topics):
                        new_trust = current_trust * edge_data['trust']
                        if neighbor not in trust_scores or new_trust > trust_scores[neighbor]:
                            trust_scores[neighbor] = new_trust
                            pq.append((-new_trust, neighbor))
        
        return trust_scores
    
    # Remove entries subsumed by more general entries with >= score
    def _remove_redundant_entries(self, trust_table: dict) -> dict:
        cleaned = {}
        by_pair = {}
        
        for (tgt, tag, chain), score in trust_table.items():
            by_pair.setdefault(tgt, []).append(((tag, chain), score))
        
        for tgt, entries in by_pair.items():
            for (tag1, chain1), score1 in entries:
                is_redundant = False
                
                for (tag2, chain2), score2 in entries:
                    if (tag1, chain1) == (tag2, chain2):
                        continue
                    
                    # Is entry2 strictly more general than entry1?
                    tag_more_general = (tag2 == '*' < tag1 != '*')
                    chain_more_general = (chain2 == '*' < chain1 != '*')
                    
                    if (tag_more_general or chain_more_general) and score2 >= score1:
                        is_redundant = True
                        break
                
                if not is_redundant:
                    cleaned[(tgt, tag1, chain1)] = score1
        
        return cleaned

    # Do topics match function
    def _topics_match(self, edge_topics: dict, query_topics: dict) -> bool:
        wildcards = {'*'}
        for dim, query_val in query_topics.items():
            edge_val = edge_topics.get(dim)
            if edge_val not in wildcards and edge_val != query_val:
                return False
        return True
