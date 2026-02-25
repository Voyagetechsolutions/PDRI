# Platform Frontend Architecture Guide

## Overview

This document outlines the architecture for building the unified Platform frontend — the single interface customers interact with. The Platform abstracts Aegis AI, PDRI, and future modules into one seamless experience.

---

## 1. Technology Stack (Recommended)

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FRONTEND STACK                                    │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Framework:        Next.js 14+ (App Router)                             │
│  Language:         TypeScript (strict mode)                             │
│  Styling:          Tailwind CSS + shadcn/ui                             │
│  State:            TanStack Query (server state) + Zustand (client)     │
│  Charts:           Recharts + D3.js (for graph visualization)           │
│  Tables:           TanStack Table                                       │
│  Forms:            React Hook Form + Zod                                │
│  Real-time:        WebSocket (native) + React Query subscriptions       │
│  Testing:          Vitest + Playwright + Testing Library                │
│  Auth:             NextAuth.js + JWT                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### Why This Stack?

| Choice | Rationale |
|--------|-----------|
| Next.js | SSR for SEO, API routes, enterprise-ready |
| TypeScript | Type safety critical for security product |
| Tailwind + shadcn | Rapid iteration, consistent design system |
| TanStack Query | Excellent caching, real-time subscriptions |
| Zustand | Simple, scalable client state |

---

## 2. Project Structure

```
platform-ui/
├── app/                          # Next.js App Router
│   ├── (auth)/                   # Auth routes (login, signup)
│   │   ├── login/
│   │   └── signup/
│   ├── (dashboard)/              # Main dashboard layout
│   │   ├── layout.tsx            # Dashboard shell
│   │   ├── page.tsx              # Dashboard home
│   │   ├── risk/                 # Risk Management
│   │   │   ├── page.tsx          # Risk overview
│   │   │   ├── findings/         # Risk findings list
│   │   │   ├── [findingId]/      # Finding detail
│   │   │   └── explorer/         # Graph explorer
│   │   ├── ai-security/          # AI Security (Aegis)
│   │   │   ├── page.tsx          # AI security dashboard
│   │   │   ├── tools/            # AI tool inventory
│   │   │   ├── policies/         # AI governance policies
│   │   │   └── alerts/           # AI-related alerts
│   │   ├── cloud/                # Cloud Security
│   │   │   ├── page.tsx          # Cloud overview
│   │   │   ├── posture/          # CSPM findings
│   │   │   ├── assets/           # Cloud asset inventory
│   │   │   └── compliance/       # Cloud compliance
│   │   ├── compliance/           # Compliance Center
│   │   │   ├── page.tsx          # Compliance dashboard
│   │   │   ├── frameworks/       # Framework views
│   │   │   ├── [framework]/      # Specific framework
│   │   │   ├── assessments/      # Assessment history
│   │   │   └── reports/          # Compliance reports
│   │   ├── simulation/           # Risk Simulation
│   │   │   ├── page.tsx          # Simulation lab
│   │   │   └── [scenarioId]/     # Scenario results
│   │   ├── investigation/        # Investigation Hub
│   │   │   ├── page.tsx          # Investigation queue
│   │   │   └── [caseId]/         # Case detail
│   │   └── settings/             # Settings
│   │       ├── page.tsx
│   │       ├── integrations/
│   │       ├── team/
│   │       └── notifications/
│   └── api/                      # API routes (BFF pattern)
│       ├── auth/
│       ├── risk/
│       ├── compliance/
│       └── webhooks/
├── components/                   # Shared components
│   ├── ui/                       # Base UI (shadcn)
│   ├── charts/                   # Chart components
│   ├── forms/                    # Form components
│   ├── layout/                   # Layout components
│   │   ├── sidebar.tsx
│   │   ├── header.tsx
│   │   └── breadcrumb.tsx
│   ├── risk/                     # Risk-specific components
│   │   ├── risk-score-badge.tsx
│   │   ├── risk-trend-chart.tsx
│   │   ├── finding-card.tsx
│   │   └── entity-graph.tsx
│   ├── ai/                       # AI security components
│   │   ├── ai-tool-card.tsx
│   │   ├── shadow-ai-alert.tsx
│   │   └── data-exposure-chart.tsx
│   └── compliance/               # Compliance components
│       ├── framework-card.tsx
│       ├── control-status.tsx
│       └── assessment-timeline.tsx
├── lib/                          # Utilities
│   ├── api/                      # API client
│   │   ├── client.ts             # Base HTTP client
│   │   ├── risk.ts               # Risk API functions
│   │   ├── compliance.ts         # Compliance API
│   │   └── simulation.ts         # Simulation API
│   ├── hooks/                    # Custom hooks
│   │   ├── use-risk-findings.ts
│   │   ├── use-compliance.ts
│   │   ├── use-websocket.ts
│   │   └── use-entity-graph.ts
│   ├── stores/                   # Zustand stores
│   │   ├── filter-store.ts
│   │   ├── selection-store.ts
│   │   └── notification-store.ts
│   ├── utils/                    # Utility functions
│   │   ├── formatters.ts
│   │   ├── risk-colors.ts
│   │   └── date-utils.ts
│   └── validations/              # Zod schemas
│       ├── finding.ts
│       └── simulation.ts
├── types/                        # TypeScript types
│   ├── api.ts                    # API response types
│   ├── risk.ts                   # Risk domain types
│   ├── compliance.ts             # Compliance types
│   └── graph.ts                  # Graph visualization types
└── public/
    └── assets/
```

---

## 3. Core Pages & Components

### 3.1 Dashboard Home

The main dashboard shows a unified view of security posture.

```tsx
// app/(dashboard)/page.tsx
export default async function DashboardPage() {
  return (
    <div className="space-y-6">
      {/* Hero Metrics */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          title="Overall Risk Score"
          value={72}
          trend="down"
          description="5% improvement from last week"
        />
        <MetricCard
          title="Active Findings"
          value={23}
          severity="high"
          description="8 critical, 15 high"
        />
        <MetricCard
          title="Compliance Score"
          value={89}
          trend="up"
          description="SOC2: 92% | HIPAA: 86%"
        />
        <MetricCard
          title="AI Tools Monitored"
          value={12}
          description="3 unsanctioned detected"
        />
      </div>

      {/* Risk Trend + Top Findings */}
      <div className="grid grid-cols-3 gap-6">
        <Card className="col-span-2">
          <CardHeader>
            <CardTitle>Risk Trend (30 Days)</CardTitle>
          </CardHeader>
          <CardContent>
            <RiskTrendChart />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Critical Findings</CardTitle>
          </CardHeader>
          <CardContent>
            <CriticalFindingsList limit={5} />
          </CardContent>
        </Card>
      </div>

      {/* Entity Risk Heatmap */}
      <Card>
        <CardHeader>
          <CardTitle>Risk Heatmap by Entity Type</CardTitle>
        </CardHeader>
        <CardContent>
          <EntityRiskHeatmap />
        </CardContent>
      </Card>

      {/* Real-time Activity Feed */}
      <Card>
        <CardHeader>
          <CardTitle>Live Activity</CardTitle>
        </CardHeader>
        <CardContent>
          <ActivityFeed />
        </CardContent>
      </Card>
    </div>
  );
}
```

### 3.2 Risk Graph Explorer

Interactive graph visualization of entities and relationships.

```tsx
// components/risk/entity-graph.tsx
'use client';

import { useCallback, useRef, useEffect } from 'react';
import * as d3 from 'd3';
import { useEntityGraph } from '@/lib/hooks/use-entity-graph';

interface EntityGraphProps {
  centerId?: string;
  depth?: number;
  onNodeClick?: (nodeId: string) => void;
}

export function EntityGraph({ centerId, depth = 2, onNodeClick }: EntityGraphProps) {
  const svgRef = useRef<SVGSVGElement>(null);
  const { data, isLoading } = useEntityGraph(centerId, depth);

  useEffect(() => {
    if (!data || !svgRef.current) return;

    const svg = d3.select(svgRef.current);
    const width = svgRef.current.clientWidth;
    const height = svgRef.current.clientHeight;

    // Clear previous
    svg.selectAll('*').remove();

    // Create simulation
    const simulation = d3.forceSimulation(data.nodes)
      .force('link', d3.forceLink(data.edges).id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2));

    // Draw edges
    const link = svg.append('g')
      .selectAll('line')
      .data(data.edges)
      .enter()
      .append('line')
      .attr('stroke', '#999')
      .attr('stroke-opacity', 0.6)
      .attr('stroke-width', d => Math.sqrt(d.weight || 1));

    // Draw nodes
    const node = svg.append('g')
      .selectAll('circle')
      .data(data.nodes)
      .enter()
      .append('circle')
      .attr('r', d => getRiskRadius(d.risk_score))
      .attr('fill', d => getRiskColor(d.risk_score))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2)
      .style('cursor', 'pointer')
      .on('click', (event, d) => onNodeClick?.(d.id))
      .call(drag(simulation));

    // Labels
    const labels = svg.append('g')
      .selectAll('text')
      .data(data.nodes)
      .enter()
      .append('text')
      .text(d => d.name)
      .attr('font-size', 10)
      .attr('dx', 12)
      .attr('dy', 4);

    // Tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);

      labels
        .attr('x', d => d.x)
        .attr('y', d => d.y);
    });

    return () => simulation.stop();
  }, [data, onNodeClick]);

  if (isLoading) return <GraphSkeleton />;

  return (
    <svg
      ref={svgRef}
      className="w-full h-[600px] border rounded-lg bg-slate-50"
    />
  );
}

function getRiskColor(score: number): string {
  if (score >= 0.85) return '#ef4444'; // critical - red
  if (score >= 0.7) return '#f97316';  // high - orange
  if (score >= 0.5) return '#eab308';  // medium - yellow
  return '#22c55e';                     // low - green
}

function getRiskRadius(score: number): number {
  return 8 + score * 12; // 8-20px based on risk
}
```

### 3.3 Risk Finding Detail

```tsx
// app/(dashboard)/risk/[findingId]/page.tsx
import { getFindingById } from '@/lib/api/risk';
import { FindingHeader } from '@/components/risk/finding-header';
import { FindingTimeline } from '@/components/risk/finding-timeline';
import { EntityList } from '@/components/risk/entity-list';
import { RecommendationList } from '@/components/risk/recommendation-list';

export default async function FindingDetailPage({
  params,
}: {
  params: { findingId: string };
}) {
  const finding = await getFindingById(params.findingId);

  return (
    <div className="space-y-6">
      {/* Header with severity, score, status */}
      <FindingHeader finding={finding} />

      <div className="grid grid-cols-3 gap-6">
        {/* Main content */}
        <div className="col-span-2 space-y-6">
          {/* Description */}
          <Card>
            <CardHeader>
              <CardTitle>Description</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-muted-foreground">{finding.description}</p>
            </CardContent>
          </Card>

          {/* Exposure Path Visualization */}
          <Card>
            <CardHeader>
              <CardTitle>Exposure Path</CardTitle>
            </CardHeader>
            <CardContent>
              <ExposurePathDiagram path={finding.exposure_path} />
            </CardContent>
          </Card>

          {/* Evidence */}
          <Card>
            <CardHeader>
              <CardTitle>Evidence ({finding.evidence.length})</CardTitle>
            </CardHeader>
            <CardContent>
              <EvidenceTable evidence={finding.evidence} />
            </CardContent>
          </Card>

          {/* Recommendations */}
          <Card>
            <CardHeader>
              <CardTitle>Recommendations</CardTitle>
            </CardHeader>
            <CardContent>
              <RecommendationList recommendations={finding.recommendations} />
            </CardContent>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Actions */}
          <Card>
            <CardHeader>
              <CardTitle>Actions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <Button className="w-full">Acknowledge</Button>
              <Button variant="outline" className="w-full">
                Mark False Positive
              </Button>
              <Button variant="outline" className="w-full">
                Create Ticket
              </Button>
            </CardContent>
          </Card>

          {/* Entities Involved */}
          <Card>
            <CardHeader>
              <CardTitle>Entities Involved</CardTitle>
            </CardHeader>
            <CardContent>
              <EntityList entities={finding.entities_involved} />
            </CardContent>
          </Card>

          {/* Activity Timeline */}
          <Card>
            <CardHeader>
              <CardTitle>Activity</CardTitle>
            </CardHeader>
            <CardContent>
              <FindingTimeline findingId={finding.finding_id} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
```

### 3.4 AI Security Dashboard

```tsx
// app/(dashboard)/ai-security/page.tsx
export default function AISecurityPage() {
  return (
    <div className="space-y-6">
      {/* AI Security Overview */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard
          title="Sanctioned AI Tools"
          value={8}
          icon={<CheckCircle className="text-green-500" />}
        />
        <MetricCard
          title="Shadow AI Detected"
          value={3}
          severity="high"
          icon={<AlertTriangle className="text-orange-500" />}
        />
        <MetricCard
          title="Data Exposures (24h)"
          value={127}
          description="42 containing PII"
        />
        <MetricCard
          title="Policy Violations"
          value={5}
          description="Today"
        />
      </div>

      {/* AI Tool Inventory */}
      <Card>
        <CardHeader>
          <CardTitle>AI Tool Inventory</CardTitle>
          <CardDescription>
            All AI tools detected in your environment
          </CardDescription>
        </CardHeader>
        <CardContent>
          <AIToolTable />
        </CardContent>
      </Card>

      {/* Data Flow to AI Tools */}
      <Card>
        <CardHeader>
          <CardTitle>Data Flow to AI Services</CardTitle>
        </CardHeader>
        <CardContent>
          <DataFlowSankey />
        </CardContent>
      </Card>

      {/* Recent AI Alerts */}
      <Card>
        <CardHeader>
          <CardTitle>Recent AI Security Alerts</CardTitle>
        </CardHeader>
        <CardContent>
          <AIAlertList />
        </CardContent>
      </Card>
    </div>
  );
}
```

### 3.5 Compliance Center

```tsx
// app/(dashboard)/compliance/page.tsx
export default function CompliancePage() {
  return (
    <div className="space-y-6">
      {/* Framework Overview Cards */}
      <div className="grid grid-cols-3 gap-4">
        <FrameworkCard
          name="SOC 2"
          score={92}
          status="compliant"
          controls={{ total: 87, passing: 80 }}
          lastAssessment="2024-01-10"
        />
        <FrameworkCard
          name="HIPAA"
          score={86}
          status="partial"
          controls={{ total: 54, passing: 46 }}
          lastAssessment="2024-01-08"
        />
        <FrameworkCard
          name="GDPR"
          score={78}
          status="partial"
          controls={{ total: 42, passing: 33 }}
          lastAssessment="2024-01-05"
        />
      </div>

      {/* Control Status by Category */}
      <Card>
        <CardHeader>
          <CardTitle>Control Status</CardTitle>
        </CardHeader>
        <CardContent>
          <ControlHeatmap />
        </CardContent>
      </Card>

      {/* Non-Compliant Controls */}
      <Card>
        <CardHeader>
          <CardTitle>Action Required</CardTitle>
          <CardDescription>Controls requiring attention</CardDescription>
        </CardHeader>
        <CardContent>
          <NonCompliantControlsTable />
        </CardContent>
      </Card>

      {/* Assessment Timeline */}
      <Card>
        <CardHeader>
          <CardTitle>Assessment History</CardTitle>
        </CardHeader>
        <CardContent>
          <AssessmentTimeline />
        </CardContent>
      </Card>
    </div>
  );
}
```

---

## 4. API Client Layer

### 4.1 Base Client

```typescript
// lib/api/client.ts
import { QueryClient } from '@tanstack/react-query';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

class APIClient {
  private baseUrl: string;
  private token: string | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setToken(token: string) {
    this.token = token;
  }

  async fetch<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const headers: HeadersInit = {
      'Content-Type': 'application/json',
      ...(this.token && { Authorization: `Bearer ${this.token}` }),
      ...options.headers,
    };

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new APIError(response.status, error.message || 'API Error');
    }

    return response.json();
  }

  get<T>(endpoint: string) {
    return this.fetch<T>(endpoint, { method: 'GET' });
  }

  post<T>(endpoint: string, body: unknown) {
    return this.fetch<T>(endpoint, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  }

  put<T>(endpoint: string, body: unknown) {
    return this.fetch<T>(endpoint, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  }

  delete<T>(endpoint: string) {
    return this.fetch<T>(endpoint, { method: 'DELETE' });
  }
}

export const apiClient = new APIClient(API_BASE_URL);

export const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30 * 1000, // 30 seconds
      refetchOnWindowFocus: false,
    },
  },
});
```

### 4.2 Risk API

```typescript
// lib/api/risk.ts
import { apiClient } from './client';
import type {
  RiskFinding,
  RiskFindingsResponse,
  RiskScore,
  EntityGraph,
} from '@/types/risk';

export async function getRiskFindings(params: {
  page?: number;
  pageSize?: number;
  severity?: string[];
  status?: string[];
}): Promise<RiskFindingsResponse> {
  const searchParams = new URLSearchParams();
  if (params.page) searchParams.set('page', String(params.page));
  if (params.pageSize) searchParams.set('page_size', String(params.pageSize));
  if (params.severity?.length) searchParams.set('severity', params.severity.join(','));
  if (params.status?.length) searchParams.set('status', params.status.join(','));

  return apiClient.get(`/api/v2/risk-findings?${searchParams}`);
}

export async function getFindingById(id: string): Promise<RiskFinding> {
  return apiClient.get(`/api/v2/risk-findings/${id}`);
}

export async function updateFindingStatus(
  id: string,
  status: string,
  reason?: string
): Promise<RiskFinding> {
  return apiClient.put(`/api/v2/risk-findings/${id}/status`, {
    status,
    status_reason: reason,
  });
}

export async function getEntityRiskScore(entityId: string): Promise<RiskScore> {
  return apiClient.get(`/api/v2/entities/${entityId}/risk-score`);
}

export async function getEntityGraph(
  centerId?: string,
  depth: number = 2
): Promise<EntityGraph> {
  const params = new URLSearchParams({ depth: String(depth) });
  if (centerId) params.set('center_id', centerId);
  return apiClient.get(`/api/v2/graph/entities?${params}`);
}
```

### 4.3 Real-time Hook

```typescript
// lib/hooks/use-websocket.ts
'use client';

import { useEffect, useRef, useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

interface WebSocketMessage {
  event_type: string;
  data: unknown;
}

export function useRiskStream() {
  const wsRef = useRef<WebSocket | null>(null);
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);

  const connect = useCallback(() => {
    const ws = new WebSocket(
      process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:8000/ws/stream'
    );

    ws.onopen = () => {
      setIsConnected(true);
      console.log('WebSocket connected');
    };

    ws.onmessage = (event) => {
      const message: WebSocketMessage = JSON.parse(event.data);

      switch (message.event_type) {
        case 'RISK_FINDING':
          // Invalidate findings query to refetch
          queryClient.invalidateQueries({ queryKey: ['risk-findings'] });
          break;
        case 'RISK_SCORE_UPDATE':
          // Update specific entity score
          queryClient.setQueryData(
            ['entity-score', message.data.entity_id],
            message.data
          );
          break;
        case 'COMPLIANCE_ALERT':
          queryClient.invalidateQueries({ queryKey: ['compliance'] });
          break;
      }
    };

    ws.onclose = () => {
      setIsConnected(false);
      // Reconnect after 3 seconds
      setTimeout(connect, 3000);
    };

    wsRef.current = ws;
  }, [queryClient]);

  useEffect(() => {
    connect();
    return () => wsRef.current?.close();
  }, [connect]);

  return { isConnected };
}
```

---

## 5. Platform Gateway API

The Platform Gateway sits between the UI and backend services:

```typescript
// This would be a separate service, but here's the API contract

/**
 * Platform Gateway API Routes
 *
 * The gateway aggregates data from multiple backend services
 * and provides a unified API for the frontend.
 */

// Risk endpoints (proxies to PDRI)
GET    /api/v2/risk-findings
GET    /api/v2/risk-findings/:id
PUT    /api/v2/risk-findings/:id/status
GET    /api/v2/entities/:id/risk-score
GET    /api/v2/entities/:id/history
GET    /api/v2/graph/entities

// AI Security endpoints (proxies to Aegis)
GET    /api/v2/ai/tools
GET    /api/v2/ai/tools/:id
GET    /api/v2/ai/alerts
POST   /api/v2/ai/policies
GET    /api/v2/ai/data-flows

// Compliance endpoints (proxies to PDRI)
GET    /api/v2/compliance/frameworks
GET    /api/v2/compliance/frameworks/:framework
POST   /api/v2/compliance/assess
GET    /api/v2/compliance/assessments/:id
GET    /api/v2/compliance/reports

// Simulation endpoints (proxies to PDRI)
POST   /api/v2/simulation/run
GET    /api/v2/simulation/:id
GET    /api/v2/simulation/scenarios

// Dashboard aggregation (combines multiple sources)
GET    /api/v2/dashboard/overview
GET    /api/v2/dashboard/metrics
GET    /api/v2/dashboard/activity

// WebSocket
WS     /ws/stream
```

---

## 6. Design System

### Color Palette for Security

```css
/* Risk severity colors */
--risk-critical: #dc2626;  /* red-600 */
--risk-high: #ea580c;      /* orange-600 */
--risk-medium: #ca8a04;    /* yellow-600 */
--risk-low: #16a34a;       /* green-600 */
--risk-info: #2563eb;      /* blue-600 */

/* Status colors */
--status-open: #dc2626;
--status-acknowledged: #f59e0b;
--status-in-progress: #3b82f6;
--status-resolved: #22c55e;

/* Compliance colors */
--compliance-pass: #22c55e;
--compliance-fail: #dc2626;
--compliance-partial: #f59e0b;
--compliance-na: #6b7280;

/* Entity type colors */
--entity-datastore: #8b5cf6;   /* violet */
--entity-service: #06b6d4;     /* cyan */
--entity-ai-tool: #ec4899;     /* pink */
--entity-identity: #f97316;    /* orange */
--entity-api: #14b8a6;         /* teal */
```

### Component Examples

```tsx
// Risk Score Badge
<Badge
  className={cn(
    'font-mono',
    score >= 85 && 'bg-red-100 text-red-800',
    score >= 70 && score < 85 && 'bg-orange-100 text-orange-800',
    score >= 50 && score < 70 && 'bg-yellow-100 text-yellow-800',
    score < 50 && 'bg-green-100 text-green-800'
  )}
>
  {score.toFixed(1)}
</Badge>

// Severity Indicator
<div className={cn(
  'w-2 h-2 rounded-full',
  severity === 'critical' && 'bg-red-500',
  severity === 'high' && 'bg-orange-500',
  severity === 'medium' && 'bg-yellow-500',
  severity === 'low' && 'bg-green-500'
)} />
```

---

## 7. Getting Started

### Prerequisites

```bash
node >= 18.0.0
pnpm >= 8.0.0
```

### Setup

```bash
# Clone the repository
git clone <platform-ui-repo>
cd platform-ui

# Install dependencies
pnpm install

# Copy environment file
cp .env.example .env.local

# Configure environment
# NEXT_PUBLIC_API_URL=http://localhost:8000
# NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/stream

# Run development server
pnpm dev
```

### Development Commands

```bash
pnpm dev          # Start dev server
pnpm build        # Production build
pnpm start        # Start production server
pnpm lint         # Run ESLint
pnpm test         # Run tests
pnpm test:e2e     # Run Playwright tests
pnpm storybook    # Component documentation
```

---

## 8. Next Steps

1. **Phase 1**: Build core dashboard and risk findings pages
2. **Phase 2**: Add AI security module
3. **Phase 3**: Add compliance center
4. **Phase 4**: Add simulation lab
5. **Phase 5**: Polish, performance optimization, accessibility
