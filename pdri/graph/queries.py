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


class IdentityQueries:
    """
    Cypher queries for identity-aware path analysis and blast radius calculation.

    These queries support:
        - Identity → Role → Permission → Resource path traversal
        - Blast radius calculation (what gets exposed if identity is compromised)
        - Access path analysis for compliance
    """

    # =========================================================================
    # Identity Path Analysis
    # =========================================================================

    FIND_IDENTITY_ACCESS_PATHS = """
    MATCH path = (identity:Identity {id: $identity_id})-[:HAS_ROLE|:MEMBER_OF*1..2]->(role:Role)
                 -[:GRANTS_PERMISSION]->(perm:Permission)-[:APPLIES_TO]->(resource)
    RETURN path,
           identity.id as identity_id,
           identity.name as identity_name,
           role.id as role_id,
           role.role_name as role_name,
           role.is_privileged as is_privileged,
           perm.id as permission_id,
           perm.action as action,
           resource.id as resource_id,
           resource.name as resource_name,
           labels(resource)[0] as resource_type,
           resource.sensitivity_likelihood as sensitivity
    ORDER BY resource.sensitivity_likelihood DESC
    LIMIT $limit
    """

    FIND_DIRECT_ACCESS_PATHS = """
    MATCH path = (identity:Identity {id: $identity_id})-[:ACCESSES|:MANAGES]->(resource)
    RETURN path,
           identity.id as identity_id,
           resource.id as resource_id,
           resource.name as resource_name,
           labels(resource)[0] as resource_type,
           resource.sensitivity_likelihood as sensitivity
    ORDER BY resource.sensitivity_likelihood DESC
    LIMIT $limit
    """

    # =========================================================================
    # Blast Radius Calculation
    # =========================================================================

    CALCULATE_BLAST_RADIUS = """
    // Find all resources an identity can access (directly or via roles)
    MATCH (identity:Identity {id: $identity_id})
    OPTIONAL MATCH role_path = (identity)-[:HAS_ROLE|:MEMBER_OF*1..3]->(role:Role)
                              -[:GRANTS_PERMISSION]->(perm:Permission)
                              -[:APPLIES_TO]->(resource)
    OPTIONAL MATCH direct_path = (identity)-[:ACCESSES|:MANAGES]->(direct_resource)
    WITH identity,
         collect(DISTINCT resource) + collect(DISTINCT direct_resource) as all_resources

    // Calculate blast radius metrics
    UNWIND all_resources as res
    WITH identity,
         count(DISTINCT res) as total_resources,
         count(DISTINCT CASE WHEN labels(res)[0] = 'DataStore' THEN res END) as data_stores,
         count(DISTINCT CASE WHEN labels(res)[0] = 'Service' THEN res END) as services,
         count(DISTINCT CASE WHEN labels(res)[0] = 'AITool' THEN res END) as ai_tools,
         sum(CASE WHEN res.sensitivity_likelihood >= 0.8 THEN 1 ELSE 0 END) as critical_resources,
         sum(CASE WHEN res.sensitivity_likelihood >= 0.5 THEN 1 ELSE 0 END) as sensitive_resources,
         avg(res.sensitivity_likelihood) as avg_sensitivity,
         max(res.sensitivity_likelihood) as max_sensitivity,
         collect(DISTINCT res.id) as resource_ids

    RETURN identity.id as identity_id,
           identity.name as identity_name,
           identity.privilege_level as privilege_level,
           total_resources,
           data_stores,
           services,
           ai_tools,
           critical_resources,
           sensitive_resources,
           avg_sensitivity,
           max_sensitivity,
           resource_ids
    """

    CALCULATE_BLAST_RADIUS_WITH_DOWNSTREAM = """
    // Find all resources an identity can access + downstream exposure
    MATCH (identity:Identity {id: $identity_id})

    // Get all accessible resources via roles
    OPTIONAL MATCH role_path = (identity)-[:HAS_ROLE|:MEMBER_OF*1..3]->(role:Role)
                              -[:GRANTS_PERMISSION]->(perm:Permission)
                              -[:APPLIES_TO]->(resource)
    OPTIONAL MATCH direct_path = (identity)-[:ACCESSES|:MANAGES]->(direct_resource)

    // Collect all directly accessible resources
    WITH identity,
         collect(DISTINCT resource) + collect(DISTINCT direct_resource) as accessible

    // Find downstream exposure (what those resources expose to)
    UNWIND accessible as res
    OPTIONAL MATCH downstream = (res)-[:EXPOSES|:MOVES_DATA_TO|:INTEGRATES_WITH*1..2]->(exposed)
    WHERE exposed:External OR exposed:AITool OR exposed.is_public = true

    WITH identity,
         accessible,
         collect(DISTINCT exposed) as exposed_to

    RETURN identity.id as identity_id,
           identity.name as identity_name,
           size(accessible) as direct_blast_radius,
           size(exposed_to) as downstream_exposure_count,
           [r IN accessible | {id: r.id, name: r.name, type: labels(r)[0], sensitivity: r.sensitivity_likelihood}] as accessible_resources,
           [e IN exposed_to | {id: e.id, name: e.name, type: labels(e)[0]}] as external_exposures
    """

    GET_PRIVILEGED_IDENTITIES = """
    MATCH (identity:Identity)-[:HAS_ROLE|:MEMBER_OF*1..2]->(role:Role)
    WHERE role.is_privileged = true
    RETURN identity.id as identity_id,
           identity.name as identity_name,
           identity.identity_type as identity_type,
           identity.has_mfa as has_mfa,
           collect(DISTINCT role.role_name) as privileged_roles,
           count(DISTINCT role) as privileged_role_count
    ORDER BY privileged_role_count DESC
    LIMIT $limit
    """

    # =========================================================================
    # Permission Analysis
    # =========================================================================

    GET_OVER_PERMISSIONED_IDENTITIES = """
    // Find identities with more permissions than they use
    MATCH (identity:Identity)-[:HAS_ROLE]->(role:Role)
                             -[:GRANTS_PERMISSION]->(perm:Permission)
                             -[:APPLIES_TO]->(resource)
    WITH identity,
         count(DISTINCT resource) as permitted_resources

    // Compare with actual access
    OPTIONAL MATCH (identity)-[access:ACCESSES]->(accessed)
    WHERE access.access_count_30d > 0

    WITH identity,
         permitted_resources,
         count(DISTINCT accessed) as actually_accessed,
         sum(access.access_count_30d) as total_accesses

    WHERE permitted_resources > 0
    RETURN identity.id as identity_id,
           identity.name as identity_name,
           permitted_resources,
           actually_accessed,
           total_accesses,
           toFloat(actually_accessed) / permitted_resources as utilization_ratio,
           permitted_resources - actually_accessed as unused_permissions
    ORDER BY unused_permissions DESC
    LIMIT $limit
    """

    GET_PERMISSIONS_FOR_RESOURCE = """
    MATCH (perm:Permission)-[:APPLIES_TO]->(resource {id: $resource_id})
    OPTIONAL MATCH (role:Role)-[:GRANTS_PERMISSION]->(perm)
    OPTIONAL MATCH (identity:Identity)-[:HAS_ROLE]->(role)
    RETURN perm.id as permission_id,
           perm.permission_name as permission_name,
           perm.action as action,
           collect(DISTINCT role.role_name) as roles,
           collect(DISTINCT identity.name) as identities,
           count(DISTINCT identity) as identity_count
    """

    # =========================================================================
    # Group Analysis
    # =========================================================================

    GET_GROUP_BLAST_RADIUS = """
    MATCH (group:Group)<-[:MEMBER_OF]-(identity:Identity)
    WITH group, collect(identity) as members

    // Get all resources accessible by group members
    UNWIND members as member
    OPTIONAL MATCH (member)-[:HAS_ROLE|:ACCESSES|:MANAGES*1..3]->(resource)
    WHERE resource:DataStore OR resource:Service OR resource:AITool

    WITH group,
         members,
         collect(DISTINCT resource) as accessible

    RETURN group.id as group_id,
           group.group_name as group_name,
           size(members) as member_count,
           size(accessible) as blast_radius,
           [r IN accessible WHERE r.sensitivity_likelihood >= 0.7 | r.id] as high_sensitivity_resources
    ORDER BY blast_radius DESC
    LIMIT $limit
    """

    # =========================================================================
    # Access Path Compliance
    # =========================================================================

    FIND_UNAUTHORIZED_ACCESS_PATHS = """
    // Find direct accesses that bypass role permissions
    MATCH (identity:Identity)-[direct:ACCESSES]->(resource)
    WHERE NOT EXISTS {
        (identity)-[:HAS_ROLE|:MEMBER_OF*1..2]->(:Role)
                  -[:GRANTS_PERMISSION]->(:Permission)
                  -[:APPLIES_TO]->(resource)
    }
    RETURN identity.id as identity_id,
           identity.name as identity_name,
           resource.id as resource_id,
           resource.name as resource_name,
           labels(resource)[0] as resource_type,
           direct.access_count_30d as access_count
    ORDER BY direct.access_count_30d DESC
    LIMIT $limit
    """


class AILineageQueries:
    """
    Cypher queries for AI data lineage tracking.

    Traces data flow through AI systems:
        DataStore → TrainingDataset → AIModel → InferenceEndpoint → ModelOutput → External

    Supports:
        - Forward lineage: Where does this data go in AI systems?
        - Backward lineage: Where did this model's training data come from?
        - Risk propagation: How does sensitive data flow through AI?
    """

    # =========================================================================
    # Forward Lineage (Data → Model → Output)
    # =========================================================================

    TRACE_DATA_TO_AI = """
    // Trace data from source to AI consumption
    MATCH path = (source:DataStore {id: $data_store_id})
                 -[:DERIVES_FROM|:MOVES_DATA_TO*0..2]->(dataset:TrainingDataset)
                 -[:TRAINED_ON]-(model:AIModel)
    RETURN path,
           source.id as source_id,
           source.name as source_name,
           source.data_classification as source_classification,
           dataset.id as dataset_id,
           dataset.dataset_name as dataset_name,
           dataset.contains_pii as contains_pii,
           model.id as model_id,
           model.model_name as model_name,
           model.is_external as is_external_model
    LIMIT $limit
    """

    TRACE_FULL_AI_LINEAGE = """
    // Full lineage: Source → Dataset → Model → Endpoint → Output → External
    MATCH path = (source:DataStore)
                 -[:DERIVES_FROM|:MOVES_DATA_TO*0..2]->(dataset:TrainingDataset)
                 -[:TRAINED_ON]-(model:AIModel)
                 -[:SERVES]-(endpoint:InferenceEndpoint)
    OPTIONAL MATCH output_path = (endpoint)-[:PRODUCES]->(output:ModelOutput)
    OPTIONAL MATCH external_path = (output)-[:EXPORTS_TO|:MOVES_DATA_TO]->(external)
    WHERE external:External OR external:AITool

    WITH source, dataset, model, endpoint, output, external,
         path, output_path, external_path
    WHERE source.sensitivity_likelihood >= $min_sensitivity

    RETURN source.id as source_id,
           source.name as source_name,
           source.sensitivity_likelihood as source_sensitivity,
           dataset.id as dataset_id,
           dataset.contains_pii as contains_pii,
           model.id as model_id,
           model.model_name as model_name,
           model.is_external as is_external,
           endpoint.id as endpoint_id,
           endpoint.is_public as is_public_endpoint,
           output.id as output_id,
           output.shared_externally as output_shared,
           external.id as external_id,
           external.name as external_name
    ORDER BY source.sensitivity_likelihood DESC
    LIMIT $limit
    """

    # =========================================================================
    # Backward Lineage (Model → Training Data → Source)
    # =========================================================================

    TRACE_MODEL_TRAINING_SOURCES = """
    // Find all data sources that contributed to a model's training
    MATCH path = (model:AIModel {id: $model_id})-[:TRAINED_ON]->(dataset:TrainingDataset)
    OPTIONAL MATCH source_path = (dataset)<-[:DERIVES_FROM|:MOVES_DATA_TO*0..3]-(source:DataStore)

    RETURN model.id as model_id,
           model.model_name as model_name,
           dataset.id as dataset_id,
           dataset.dataset_name as dataset_name,
           dataset.contains_pii as contains_pii,
           dataset.contains_secrets as contains_secrets,
           dataset.data_categories as data_categories,
           collect(DISTINCT {
               id: source.id,
               name: source.name,
               classification: source.data_classification,
               sensitivity: source.sensitivity_likelihood
           }) as data_sources
    """

    TRACE_MODEL_CHAIN = """
    // Find model fine-tuning chain (base model → fine-tuned models)
    MATCH chain = (base:AIModel)<-[:FINE_TUNED_FROM*0..5]-(derived:AIModel {id: $model_id})
    RETURN [node IN nodes(chain) | {
               id: node.id,
               name: node.model_name,
               is_external: node.is_external,
               training_sensitivity: node.training_data_sensitivity
           }] as model_chain,
           length(chain) as chain_length
    """

    # =========================================================================
    # Risk Propagation Analysis
    # =========================================================================

    FIND_SENSITIVE_DATA_IN_AI = """
    // Find sensitive data that's being used by AI systems
    MATCH (source:DataStore)-[:DERIVES_FROM|:MOVES_DATA_TO*0..2]->(dataset:TrainingDataset)
                            -[:TRAINED_ON]-(model:AIModel)
    WHERE source.sensitivity_likelihood >= $min_sensitivity
       OR dataset.contains_pii = true
       OR dataset.contains_secrets = true

    RETURN source.id as source_id,
           source.name as source_name,
           source.data_classification as classification,
           source.sensitivity_likelihood as sensitivity,
           dataset.id as dataset_id,
           dataset.contains_pii as contains_pii,
           dataset.contains_secrets as contains_secrets,
           model.id as model_id,
           model.model_name as model_name,
           model.is_external as is_external,
           model.can_memorize_data as can_memorize
    ORDER BY source.sensitivity_likelihood DESC, model.is_external DESC
    LIMIT $limit
    """

    FIND_EXTERNAL_AI_EXPOSURE = """
    // Find data exposed to external AI systems
    MATCH (source:DataStore)-[:DERIVES_FROM|:MOVES_DATA_TO*0..3]->(dataset)
                            -[:TRAINED_ON|:FEEDS_INTO*1..2]-(ai)
    WHERE (ai:AIModel AND ai.is_external = true)
       OR (ai:AITool AND ai.sends_data_external = true)

    RETURN source.id as source_id,
           source.name as source_name,
           source.sensitivity_likelihood as sensitivity,
           ai.id as ai_id,
           ai.name as ai_name,
           labels(ai)[0] as ai_type,
           CASE WHEN ai:AIModel THEN ai.vendor ELSE ai.vendor END as vendor
    ORDER BY source.sensitivity_likelihood DESC
    LIMIT $limit
    """

    FIND_MODEL_OUTPUT_EXPOSURE = """
    // Find where AI model outputs are exposed
    MATCH (model:AIModel)-[:SERVES]-(endpoint:InferenceEndpoint)
                         -[:PRODUCES]->(output:ModelOutput)
    OPTIONAL MATCH (output)-[:EXPORTS_TO|:MOVES_DATA_TO]->(dest)

    RETURN model.id as model_id,
           model.model_name as model_name,
           endpoint.id as endpoint_id,
           endpoint.is_public as is_public,
           output.id as output_id,
           output.output_type as output_type,
           output.shared_externally as shared_externally,
           dest.id as destination_id,
           labels(dest)[0] as destination_type
    ORDER BY endpoint.is_public DESC, output.shared_externally DESC
    LIMIT $limit
    """

    # =========================================================================
    # Compliance & Governance
    # =========================================================================

    GET_AI_DATA_INVENTORY = """
    // Get inventory of all data used in AI systems
    MATCH (dataset:TrainingDataset)-[:TRAINED_ON]-(model:AIModel)
    OPTIONAL MATCH (dataset)<-[:DERIVES_FROM|:MOVES_DATA_TO*0..2]-(source:DataStore)

    RETURN dataset.id as dataset_id,
           dataset.dataset_name as dataset_name,
           dataset.data_classification as classification,
           dataset.contains_pii as contains_pii,
           dataset.contains_secrets as contains_secrets,
           dataset.data_categories as categories,
           collect(DISTINCT source.id) as source_ids,
           collect(DISTINCT model.id) as model_ids,
           count(DISTINCT model) as model_count
    ORDER BY dataset.data_classification DESC
    """

    GET_MODELS_BY_DATA_SENSITIVITY = """
    // Group models by the sensitivity of their training data
    MATCH (model:AIModel)-[:TRAINED_ON]->(dataset:TrainingDataset)
    OPTIONAL MATCH (dataset)<-[:DERIVES_FROM*0..2]-(source:DataStore)

    WITH model,
         max(source.sensitivity_likelihood) as max_source_sensitivity,
         max(CASE dataset.data_classification
             WHEN 'restricted' THEN 4
             WHEN 'confidential' THEN 3
             WHEN 'internal' THEN 2
             WHEN 'public' THEN 1
             ELSE 0 END) as max_classification

    RETURN model.id as model_id,
           model.model_name as model_name,
           model.is_external as is_external,
           model.vendor as vendor,
           max_source_sensitivity as data_sensitivity,
           CASE max_classification
               WHEN 4 THEN 'restricted'
               WHEN 3 THEN 'confidential'
               WHEN 2 THEN 'internal'
               WHEN 1 THEN 'public'
               ELSE 'unknown'
           END as highest_classification
    ORDER BY max_source_sensitivity DESC, max_classification DESC
    LIMIT $limit
    """

    # =========================================================================
    # Impact Analysis
    # =========================================================================

    CALCULATE_DATA_AI_BLAST_RADIUS = """
    // Calculate blast radius if a data source is compromised (AI impact)
    MATCH (source:DataStore {id: $data_store_id})

    // Find all datasets derived from this source
    OPTIONAL MATCH (source)-[:DERIVES_FROM|:MOVES_DATA_TO*0..3]->(dataset:TrainingDataset)

    // Find all models trained on those datasets
    OPTIONAL MATCH (dataset)-[:TRAINED_ON]-(model:AIModel)

    // Find all endpoints serving those models
    OPTIONAL MATCH (model)-[:SERVES]-(endpoint:InferenceEndpoint)

    // Find all outputs from those endpoints
    OPTIONAL MATCH (endpoint)-[:PRODUCES]->(output:ModelOutput)

    RETURN source.id as source_id,
           source.name as source_name,
           count(DISTINCT dataset) as affected_datasets,
           count(DISTINCT model) as affected_models,
           count(DISTINCT CASE WHEN model.is_external THEN model END) as external_models,
           count(DISTINCT endpoint) as affected_endpoints,
           count(DISTINCT CASE WHEN endpoint.is_public THEN endpoint END) as public_endpoints,
           count(DISTINCT output) as affected_outputs,
           collect(DISTINCT model.id) as model_ids,
           collect(DISTINCT endpoint.id) as endpoint_ids
    """
