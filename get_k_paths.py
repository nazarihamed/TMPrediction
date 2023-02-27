import json, ast
import networkx as nx
from itertools import islice
import setting
'''k shorthest paths --> removed from C0 since huge CPU consumption
Now I calculate k_spaths outside, the agent just will know it '''

def k_shortest_paths(graph, src, dst, k, weight='weight'):
    return list(islice(nx.shortest_simple_paths(graph, src, dst, weight=weight), k))

def all_k_shortest_paths(graph, weight='weight', k=10,num_nodes=0):
    """
        Get all K shortest paths between datapaths.
        paths = {dp1:{dp2:[[path1], [path2],...,[pathk]]},}
    """
    _graph = graph.copy()
    paths = {}
    # Find k shortest paths in graph.
    for src in _graph.nodes():
        paths.setdefault(src, {})
        for dst in _graph.nodes():
            if src != dst:
                paths[src].setdefault(dst, [])
                paths[src][dst] = k_shortest_paths(_graph, src, dst, weight=weight, k=k)
    print(paths)
    with open('paths/k_paths_'+str(num_nodes)+'Nodes.json','w') as json_file:
        json.dump(paths, json_file, indent=2) 

def get_k_paths(num_nodes):
    file = 'paths/k_paths_'+str(num_nodes)+'Nodes.json'
    with open(file,'r') as json_file:
        k_shortest_paths = json.load(json_file)
        k_shortest_paths = ast.literal_eval(json.dumps(k_shortest_paths))
    return k_shortest_paths

num_nodes = setting.NUMBER_OF_NODES
k = 10
file = 'paths/graph_'+str(num_nodes)+'Nodes.json'
with open(file,'r') as json_file:
    graph_dict = json.load(json_file)
    graph_dict = ast.literal_eval(json.dumps(graph_dict))
graph_dict = {int(k):{int(sk):sv for sk,sv in graph_dict[k].items() } for k,v in graph_dict.items() }
# print(graph_dict)

graph_nx = nx.from_dict_of_dicts(graph_dict)
print(graph_nx)
all_k_shortest_paths(graph_nx, weight='weight', k=k, num_nodes=num_nodes)

sp = get_k_paths(num_nodes)
print(sp)