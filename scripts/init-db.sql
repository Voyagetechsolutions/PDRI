-- =============================================================================
-- PDRI - Database Initialization Script
-- =============================================================================
-- Creates the initial PostgreSQL schema for:
--   - Risk score history
--   - Trajectory tracking
--   - Event metadata
--   - Model registry (Phase 2)
-- =============================================================================

-- Create schemas
CREATE SCHEMA IF NOT EXISTS risk;
CREATE SCHEMA IF NOT EXISTS events;
CREATE SCHEMA IF NOT EXISTS ml;

-- =============================================================================
-- Risk Schema - Score History & Trajectories
-- =============================================================================

-- Entity risk score snapshots
CREATE TABLE IF NOT EXISTS risk.score_history (
    id BIGSERIAL PRIMARY KEY,
    entity_id VARCHAR(255) NOT NULL,
    entity_type VARCHAR(50) NOT NULL,
    exposure_score DECIMAL(5,4) NOT NULL,
    volatility_score DECIMAL(5,4) NOT NULL,
    sensitivity_likelihood DECIMAL(5,4) NOT NULL,
    composite_score DECIMAL(5,4) NOT NULL,
    scoring_version VARCHAR(20) NOT NULL DEFAULT '1.0.0',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB
);

-- Index for efficient time-range queries
CREATE INDEX IF NOT EXISTS idx_score_history_entity_time 
    ON risk.score_history(entity_id, created_at DESC);

-- Trajectory analysis cache
CREATE TABLE IF NOT EXISTS risk.trajectories (
    id BIGSERIAL PRIMARY KEY,
    entity_id VARCHAR(255) NOT NULL,
    window_days INTEGER NOT NULL,
    trend_direction VARCHAR(20) NOT NULL,
    start_score DECIMAL(5,4) NOT NULL,
    end_score DECIMAL(5,4) NOT NULL,
    score_delta DECIMAL(5,4) NOT NULL,
    volatility DECIMAL(5,4) NOT NULL,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    valid_until TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_trajectories_entity 
    ON risk.trajectories(entity_id, calculated_at DESC);

-- =============================================================================
-- Events Schema - Processed Event Metadata
-- =============================================================================

-- Processed security events (metadata only, not raw data)
CREATE TABLE IF NOT EXISTS events.processed_events (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(255) UNIQUE NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    source_system_id VARCHAR(255) NOT NULL,
    target_entity_id VARCHAR(255),
    identity_id VARCHAR(255),
    exposure_direction VARCHAR(50),
    sensitivity_tags VARCHAR(50)[],
    privilege_level VARCHAR(50),
    data_volume_estimate BIGINT,
    processed_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    processing_status VARCHAR(20) DEFAULT 'processed',
    error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_source 
    ON events.processed_events(source_system_id, event_timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_events_type 
    ON events.processed_events(event_type, event_timestamp DESC);

-- Dead letter queue for failed events
CREATE TABLE IF NOT EXISTS events.dead_letter (
    id BIGSERIAL PRIMARY KEY,
    raw_event JSONB NOT NULL,
    error_type VARCHAR(100) NOT NULL,
    error_message TEXT,
    retry_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_retry_at TIMESTAMP WITH TIME ZONE
);

-- =============================================================================
-- ML Schema - Model Registry (Phase 2+)
-- =============================================================================

-- Registered models
CREATE TABLE IF NOT EXISTS ml.models (
    id BIGSERIAL PRIMARY KEY,
    model_name VARCHAR(255) NOT NULL,
    model_version VARCHAR(50) NOT NULL,
    model_type VARCHAR(100) NOT NULL,
    status VARCHAR(20) DEFAULT 'inactive',
    artifact_path TEXT,
    metrics JSONB,
    hyperparameters JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    activated_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(model_name, model_version)
);

-- Model predictions log
CREATE TABLE IF NOT EXISTS ml.predictions (
    id BIGSERIAL PRIMARY KEY,
    model_id BIGINT REFERENCES ml.models(id),
    entity_id VARCHAR(255) NOT NULL,
    prediction_type VARCHAR(50) NOT NULL,
    prediction_value JSONB NOT NULL,
    confidence DECIMAL(5,4),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_predictions_entity 
    ON ml.predictions(entity_id, created_at DESC);

-- =============================================================================
-- Audit Table for Compliance (Phase 4)
-- =============================================================================

CREATE TABLE IF NOT EXISTS risk.audit_log (
    id BIGSERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    actor VARCHAR(255),
    entity_type VARCHAR(50),
    entity_id VARCHAR(255),
    old_value JSONB,
    new_value JSONB,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address INET,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
    ON risk.audit_log(timestamp DESC);

-- =============================================================================
-- Functions
-- =============================================================================

-- Function to calculate composite risk score
CREATE OR REPLACE FUNCTION risk.calculate_composite_score(
    exposure DECIMAL,
    volatility DECIMAL,
    sensitivity DECIMAL
) RETURNS DECIMAL AS $$
BEGIN
    -- Weighted average: 50% exposure, 30% volatility, 20% sensitivity
    RETURN (exposure * 0.5) + (volatility * 0.3) + (sensitivity * 0.2);
END;
$$ LANGUAGE plpgsql;

-- =============================================================================
-- Initial Data (Optional test data)
-- =============================================================================

-- Insert initial scoring version record
INSERT INTO risk.score_history (entity_id, entity_type, exposure_score, volatility_score, sensitivity_likelihood, composite_score, scoring_version, metadata)
VALUES ('system:pdri:init', 'system', 0.0, 0.0, 0.0, 0.0, '1.0.0', '{"note": "Initial system record"}')
ON CONFLICT DO NOTHING;

COMMENT ON TABLE risk.score_history IS 'Historical risk scores for all graph entities';
COMMENT ON TABLE risk.trajectories IS 'Pre-calculated risk trajectories for dashboard queries';
COMMENT ON TABLE events.processed_events IS 'Metadata from processed security events';
COMMENT ON TABLE ml.models IS 'Machine learning model registry (Phase 2+)';
