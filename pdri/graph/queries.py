"""
PDRI Graph Queries
==================

Cypher query templates for Neo4j graph operations.

This module provides parameterized Cypher queries for:
    - Node CRUD operations
    - Edge CRUD operations
    - Graph traversal and pathfinding
    - Risk-related analytics

All queries use parameterized inputs to prevent injection attacks.

Author: PDRI Team
Version: 1.0.0
"""


class NodeQueries:
    """
    Cypher queries for node operations.
    """
    
    # =========================================================================
    # Create Operations
    # =========================================================================
    
    CREATE_NODE = """
    CREATE (n:{label} $properties)
    RETURN n
    """
    
    MERGE_NODE = """
    MERGE (n:{label} {{id: $id}})
    SET n += $properties
    RETURN n
    """
    
    # =========================================================================
    # Read Operations
    # =========================================================================
    
    GET_NODE_BY_ID = """
    MATCH (n {{id: $id}})
    RETURN n
    """
    
    GET_NODES_BY_TYPE = """
    MATCH (n:{label})
    RETURN n
    ORDER BY n.created_at DESC
    SKIP $skip
    LIMIT $limit
    """
    
    GET_NODE_WITH_RELATIONSHIPS = """
    MATCH (n {{id: $id}})
    OPTIONAL MATCH (n)-[r]-(m)
    RETURN n, collect(DISTINCT {{
        relationship: type(r),
        direction: CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END,
        connected_node: m.id,
        connected_type: labels(m)[0]
    }}) as relationships
    """
    
    COUNT_NODES_BY_TYPE = """
    MATCH (n:{label})
    RETURN count(n) as count
    """
    
    # =========================================================================
    # Update Operations
    # =========================================================================
    
    UPDATE_NODE = """
    MATCH (n {{id: $id}})
    SET n += $properties
    SET n.updated_at = datetime()
    RETURN n
    """
    
    UPDATE_RISK_SCORES = """
    MATCH (n {{id: $id}})
    SET n.exposure_score = $exposure_score,
        n.volatility_score = $volatility_score,
        n.sensitivity_likelihood = $sensitivity_likelihood,
        n.updated_at = datetime()
    RETURN n
    """
    
    # =========================================================================
    # Delete Operations
    # =========================================================================
    
    DELETE_NODE = """
    MATCH (n {{id: $id}})
    DETACH DELETE n
    """
    
    DELETE_NODES_BY_TYPE = """
    MATCH (n:{label})
    DETACH DELETE n
    """


class EdgeQueries:
    """
    Cypher queries for edge (relationship) operations.
    """
    
    # =========================================================================
    # Create Operations  
    # =========================================================================
    
    CREATE_EDGE = """
    MATCH (a {{id: $source_id}}), (b {{id: $target_id}})
    CREATE (a)-[r:{rel_type} $properties]->(b)
    RETURN r
    """
    
    MERGE_EDGE = """
    MATCH (a {{id: $source_id}}), (b {{id: $target_id}})
    MERGE (a)-[r:{rel_type}]->(b)
    SET r += $properties
    RETURN r
    """
    
    # =========================================================================
    # Read Operations
    # =========================================================================
    
    GET_EDGES_FROM_NODE = """
    MATCH (n {{id: $node_id}})-[r]->(m)
    RETURN r, m.id as target_id, labels(m)[0] as target_type
    """
    
    GET_EDGES_TO_NODE = """
    MATCH (m)-[r]->(n {{id: $node_id}})
    RETURN r, m.id as source_id, labels(m)[0] as source_type
    """
    
    GET_ALL_EDGES_FOR_NODE = """
    MATCH (n {{id: $node_id}})-[r]-(m)
    RETURN r, 
           m.id as connected_id,
           labels(m)[0] as connected_type,
           CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END as direction
    """
    
    # =========================================================================
    # Update Operations
    # =========================================================================
    
    UPDATE_EDGE = """
    MATCH (a {{id: $source_id}})-[r:{rel_type}]->(b {{id: $target_id}})
    SET r += $properties
    RETURN r
    """
    
    INCREMENT_ACCESS_COUNT = """
    MATCH (a {{id: $source_id}})-[r:ACCESSES]->(b {{id: $target_id}})
    SET r.access_count_30d = COALESCE(r.access_count_30d, 0) + 1,
        r.last_activity = datetime()
    RETURN r
    """
    
    # =========================================================================
    # Delete Operations
    # =========================================================================
    
    DELETE_EDGE = """
    MATCH (a {{id: $source_id}})-[r:{rel_type}]->(b {{id: $target_id}})
    DELETE r
    """


class PathQueries:
    """
    Cypher queries for graph traversal and pathfinding.
    """
    
    # =========================================================================
    # Exposure Path Finding
    # =========================================================================
    
    FIND_EXPOSURE_PATHS = """
    MATCH path = (source {{id: $source_id}})-[*1..{max_depth}]->(target)
    WHERE target:External OR target:AITool OR target.is_public = true
    RETURN path,
           length(path) as path_length,
           [n in nodes(path) | n.id] as node_ids,
           [r in relationships(path) | type(r)] as relationship_types
    ORDER BY path_length
    LIMIT $limit
    """
    
    FIND_SHORTEST_PATH = """
    MATCH path = shortestPath(
        (source {{id: $source_id}})-[*..{max_depth}]-(target {{id: $target_id}})
    )
    RETURN path,
           length(path) as path_length,
           [n in nodes(path) | n.id] as node_ids
    """
    
    FIND_ALL_PATHS = """
    MATCH path = (source {{id: $source_id}})-[*1..{max_depth}]-(target {{id: $target_id}})
    RETURN path,
           length(path) as path_length,
           [n in nodes(path) | {{id: n.id, type: labels(n)[0], score: n.exposure_score}}] as nodes_detail
    ORDER BY path_length
    LIMIT $limit
    """
    
    # =========================================================================
    # AI Tool Exposure
    # =========================================================================
    
    FIND_AI_EXPOSURE_PATHS = """
    MATCH path = (ds:DataStore)-[*1..{max_depth}]->(ai:AITool)
    WHERE ds.sensitivity_likelihood > $min_sensitivity
    RETURN path,
           ds.id as data_store_id,
           ds.name as data_store_name,
           ds.sensitivity_likelihood as sensitivity,
           ai.id as ai_tool_id,
           ai.name as ai_tool_name,
           ai.is_sanctioned as is_sanctioned,
           length(path) as path_length
    ORDER BY ds.sensitivity_likelihood DESC
    LIMIT $limit
    """
    
    GET_AI_TOOLS_ACCESSING_DATA = """
    MATCH (ai:AITool)-[r]->(ds:DataStore {{id: $data_store_id}})
    RETURN ai,
           type(r) as relationship,
           r.access_count_30d as access_count
    ORDER BY r.access_count_30d DESC
    """
    
    # =========================================================================
    # Neighbor Discovery
    # =========================================================================
    
    GET_NEIGHBORS = """
    MATCH (n {{id: $node_id}})-[r]-(neighbor)
    RETURN neighbor,
           type(r) as relationship,
           CASE WHEN startNode(r) = n THEN 'outgoing' ELSE 'incoming' END as direction
    ORDER BY neighbor.exposure_score DESC
    LIMIT $limit
    """
    
    GET_NEIGHBORS_BY_TYPE = """
    MATCH (n {{id: $node_id}})-[r]-(neighbor:{label})
    RETURN neighbor,
           type(r) as relationship
    ORDER BY neighbor.exposure_score DESC
    """


class AnalyticsQueries:
    """
    Cypher queries for risk analytics and centrality calculations.
    """
    
    # =========================================================================
    # Centrality
    # =========================================================================
    
    GET_HIGH_CENTRALITY_NODES = """
    MATCH (n)
    WITH n, size((n)-[]-()) as degree
    WHERE degree > $min_degree
    RETURN n.id as id,
           n.name as name,
           labels(n)[0] as type,
           degree,
           n.exposure_score as exposure_score
    ORDER BY degree DESC
    LIMIT $limit
    """
    
    GET_BETWEENNESS_APPROXIMATION = """
    MATCH (n)
    WHERE n.exposure_score > $min_score
    OPTIONAL MATCH path1 = (a)-[*..2]->(n)
    OPTIONAL MATCH path2 = (n)-[*..2]->(b)
    WITH n, count(DISTINCT a) as incoming, count(DISTINCT b) as outgoing
    RETURN n.id as id,
           n.name as name,
           incoming + outgoing as connectivity,
           incoming,
           outgoing,
           n.exposure_score as exposure_score
    ORDER BY incoming + outgoing DESC
    LIMIT $limit
    """
    
    # =========================================================================
    # Risk Aggregations
    # =========================================================================
    
    GET_HIGH_RISK_NODES = """
    MATCH (n)
    WHERE n.exposure_score >= $threshold
    RETURN n.id as id,
           n.name as name,
           labels(n)[0] as type,
           n.exposure_score as exposure_score,
           n.volatility_score as volatility_score,
           n.sensitivity_likelihood as sensitivity_likelihood
    ORDER BY n.exposure_score DESC
    LIMIT $limit
    """
    
    GET_RISK_BY_TYPE = """
    MATCH (n:{label})
    RETURN avg(n.exposure_score) as avg_exposure,
           max(n.exposure_score) as max_exposure,
           min(n.exposure_score) as min_exposure,
           avg(n.volatility_score) as avg_volatility,
           count(n) as node_count
    """
    
    GET_RISK_DISTRIBUTION = """
    MATCH (n)
    WITH n,
         CASE 
           WHEN n.exposure_score >= 0.8 THEN 'critical'
           WHEN n.exposure_score >= 0.6 THEN 'high'
           WHEN n.exposure_score >= 0.4 THEN 'medium'
           WHEN n.exposure_score >= 0.2 THEN 'low'
           ELSE 'minimal'
         END as risk_level
    RETURN risk_level, count(n) as count
    ORDER BY 
         CASE risk_level
           WHEN 'critical' THEN 1
           WHEN 'high' THEN 2
           WHEN 'medium' THEN 3
           WHEN 'low' THEN 4
           ELSE 5
         END
    """
    
    # =========================================================================
    # Data Flow Analysis
    # =========================================================================
    
    GET_DATA_FLOW_SUMMARY = """
    MATCH (source)-[r:MOVES_DATA_TO]->(target)
    RETURN source.id as source_id,
           source.name as source_name,
           target.id as target_id,
           target.name as target_name,
           r.data_volume_bytes as volume,
           r.last_activity as last_activity
    ORDER BY r.data_volume_bytes DESC
    LIMIT $limit
    """
    
    GET_EXTERNAL_EXPOSURES = """
    MATCH (internal)-[r:EXPOSES|MOVES_DATA_TO]->(external)
    WHERE external:External OR external:AITool OR external.is_public = true
    RETURN internal.id as internal_id,
           internal.name as internal_name,
           labels(internal)[0] as internal_type,
           type(r) as relationship,
           external.id as external_id,
           external.name as external_name,
           labels(external)[0] as external_type,
           internal.sensitivity_likelihood as sensitivity
    ORDER BY internal.sensitivity_likelihood DESC
    LIMIT $limit
    """
