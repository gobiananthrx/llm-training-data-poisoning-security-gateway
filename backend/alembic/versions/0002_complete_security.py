"""complete security tables

Revision ID: 0002_complete_security
Revises: 8dba97f9040d
Create Date: 2026-09-08 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0002_complete_security'
down_revision: Union[str, Sequence[str], None] = '8dba97f9040d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    # 1. Add record_count to dataset_versions if not exists
    if 'dataset_versions' in existing_tables:
        columns = [c['name'] for c in inspector.get_columns('dataset_versions')]
        if 'record_count' not in columns:
            op.add_column('dataset_versions', sa.Column('record_count', sa.Integer(), nullable=True))

    # 2. agent_runs
    if 'agent_runs' not in existing_tables:
        op.create_table(
            'agent_runs',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('agent_name', sa.String(length=50), nullable=False),
            sa.Column('status', sa.String(length=30), nullable=False, server_default='PENDING'),
            sa.Column('provider', sa.String(length=50), nullable=True),
            sa.Column('duration_ms', sa.Integer(), nullable=True),
            sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('error_message', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_agent_runs_version_id', 'agent_runs', ['version_id'])
        op.create_index('ix_agent_runs_agent_name', 'agent_runs', ['agent_name'])

    # 3. agent_findings
    if 'agent_findings' not in existing_tables:
        op.create_table(
            'agent_findings',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('finding_id', sa.String(length=50), unique=True, nullable=False),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('agent_run_id', sa.Integer(), sa.ForeignKey('agent_runs.id', ondelete='SET NULL'), nullable=True),
            sa.Column('agent', sa.String(length=50), nullable=False),
            sa.Column('status', sa.String(length=20), nullable=False, server_default='FLAGGED'),
            sa.Column('record_id', sa.String(length=100), nullable=False),
            sa.Column('field', sa.String(length=100), nullable=False),
            sa.Column('location', sa.JSON(), nullable=False),
            sa.Column('category', sa.String(length=100), nullable=False),
            sa.Column('severity', sa.String(length=20), nullable=False),
            sa.Column('confidence', sa.Float(), nullable=False),
            sa.Column('evidence', sa.Text(), nullable=False),
            sa.Column('reason', sa.Text(), nullable=False),
            sa.Column('recommendation', sa.String(length=30), nullable=False),
            sa.Column('entity_type', sa.String(length=50), nullable=True),
            sa.Column('related_record_ids', sa.JSON(), nullable=True),
            sa.Column('model_or_provider', sa.String(length=50), nullable=True),
            sa.Column('metadata_json', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_agent_findings_finding_id', 'agent_findings', ['finding_id'])
        op.create_index('ix_agent_findings_version_id', 'agent_findings', ['version_id'])
        op.create_index('ix_agent_findings_agent_run_id', 'agent_findings', ['agent_run_id'])
        op.create_index('ix_agent_findings_agent', 'agent_findings', ['agent'])
        op.create_index('ix_agent_findings_record_id', 'agent_findings', ['record_id'])
        op.create_index('ix_agent_findings_category', 'agent_findings', ['category'])
        op.create_index('ix_agent_findings_severity', 'agent_findings', ['severity'])

    # 4. correlated_findings
    if 'correlated_findings' not in existing_tables:
        op.create_table(
            'correlated_findings',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('correlation_id', sa.String(length=50), unique=True, nullable=False),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('record_id', sa.String(length=100), nullable=False),
            sa.Column('field', sa.String(length=100), nullable=False),
            sa.Column('location', sa.JSON(), nullable=False),
            sa.Column('primary_category', sa.String(length=100), nullable=False),
            sa.Column('max_severity', sa.String(length=20), nullable=False),
            sa.Column('agents_involved', sa.JSON(), nullable=False),
            sa.Column('finding_ids', sa.JSON(), nullable=False),
            sa.Column('agent_summaries', sa.JSON(), nullable=False),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_correlated_findings_correlation_id', 'correlated_findings', ['correlation_id'])
        op.create_index('ix_correlated_findings_version_id', 'correlated_findings', ['version_id'])
        op.create_index('ix_correlated_findings_record_id', 'correlated_findings', ['record_id'])
        op.create_index('ix_correlated_findings_max_severity', 'correlated_findings', ['max_severity'])

    # 5. risk_assessments
    if 'risk_assessments' not in existing_tables:
        op.create_table(
            'risk_assessments',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('risk_score', sa.Integer(), nullable=False),
            sa.Column('risk_level', sa.String(length=20), nullable=False),
            sa.Column('contributing_factors', sa.JSON(), nullable=False),
            sa.Column('explanation', sa.Text(), nullable=False),
            sa.Column('metrics', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_risk_assessments_version_id', 'risk_assessments', ['version_id'])
        op.create_index('ix_risk_assessments_risk_level', 'risk_assessments', ['risk_level'])

    # 6. policy_decisions
    if 'policy_decisions' not in existing_tables:
        op.create_table(
            'policy_decisions',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('decision', sa.String(length=30), nullable=False),
            sa.Column('policy_input', sa.JSON(), nullable=False),
            sa.Column('policy_output', sa.JSON(), nullable=False),
            sa.Column('reasons', sa.JSON(), nullable=False),
            sa.Column('evaluated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_policy_decisions_version_id', 'policy_decisions', ['version_id'])
        op.create_index('ix_policy_decisions_decision', 'policy_decisions', ['decision'])

    # 7. human_reviews
    if 'human_reviews' not in existing_tables:
        op.create_table(
            'human_reviews',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('version_id', sa.Integer(), sa.ForeignKey('dataset_versions.id', ondelete='CASCADE'), nullable=False),
            sa.Column('action', sa.String(length=30), nullable=False),
            sa.Column('notes', sa.Text(), nullable=True),
            sa.Column('changes_summary', sa.JSON(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        )
        op.create_index('ix_human_reviews_version_id', 'human_reviews', ['version_id'])
        op.create_index('ix_human_reviews_action', 'human_reviews', ['action'])

    # 8. audit_events
    if 'audit_events' not in existing_tables:
        op.create_table(
            'audit_events',
            sa.Column('id', sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column('event_type', sa.String(length=100), nullable=False),
            sa.Column('dataset_id', sa.String(length=50), nullable=False),
            sa.Column('version', sa.Integer(), nullable=False),
            sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
            sa.Column('details', sa.JSON(), nullable=True),
        )
        op.create_index('ix_audit_events_dataset_id', 'audit_events', ['dataset_id'])
        op.create_index('ix_audit_events_event_type', 'audit_events', ['event_type'])
        op.create_index('ix_audit_events_timestamp', 'audit_events', ['timestamp'])


def downgrade() -> None:
    op.drop_table('audit_events')
    op.drop_table('human_reviews')
    op.drop_table('policy_decisions')
    op.drop_table('risk_assessments')
    op.drop_table('correlated_findings')
    op.drop_table('agent_findings')
    op.drop_table('agent_runs')
    op.drop_column('dataset_versions', 'record_count')
