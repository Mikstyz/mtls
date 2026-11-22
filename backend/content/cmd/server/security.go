package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// Runtime may create and edit drafts but must not publish or remove content directly.
func validateRuntimePrivileges(ctx context.Context, db *sql.DB) error {
	if err := validateOutboxProtection(ctx, db); err != nil {
		return err
	}
	if err := validateReactionPrivileges(ctx, db, true); err != nil {
		return err
	}

	const query = `SELECT
        COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname=current_user), true)
        OR EXISTS (SELECT 1 FROM pg_class WHERE oid=ANY(ARRAY['content_posts'::regclass, 'content_post_media'::regclass, 'content_draft_requests'::regclass, 'content_author_purges'::regclass]) AND pg_has_role(current_user, relowner, 'MEMBER'))
        OR EXISTS (SELECT 1 FROM pg_proc WHERE oid = 'content_guard_draft_edit()'::regprocedure AND pg_has_role(current_user, proowner, 'MEMBER'))
        OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'content_posts'::regclass AND tgname = 'content_guard_draft_edit' AND tgfoid = 'content_guard_draft_edit()'::regprocedure AND tgenabled IN ('O', 'A') AND NOT tgisinternal)
        OR has_table_privilege(current_user, 'content_posts', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_post_media', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_posts', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_post_media', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_posts', 'DELETE')
        OR has_column_privilege(current_user, 'content_posts', 'id', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'author_id', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'media_kind', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'visibility', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'hidden_by_case', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'hidden_by_case', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'status', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'created_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'author_removed_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'video_duration_ms', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'video_duration_ms', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'published_edition', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_edition', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'status', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'visibility', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'published_at', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'author_removed_at', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'created_at', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'revision', 'INSERT')
        OR has_table_privilege(current_user, 'content_draft_requests', 'DELETE')
        OR has_any_column_privilege(current_user, 'content_draft_requests', 'UPDATE')
        OR has_table_privilege(current_user, 'content_post_media', 'DELETE')
        OR has_any_column_privilege(current_user, 'content_post_media', 'INSERT')
        OR has_any_column_privilege(current_user, 'content_post_media', 'UPDATE')
        OR has_table_privilege(current_user, 'content_author_purges', 'DELETE')
        OR has_any_column_privilege(current_user, 'content_author_purges', 'INSERT')
        OR has_any_column_privilege(current_user, 'content_author_purges', 'UPDATE')`

	var excessive bool

	if err := db.QueryRowContext(ctx, query).Scan(&excessive); err != nil {
		return fmt.Errorf("check content runtime privileges: %w", err)
	}

	if excessive {
		return errors.New("content runtime database role has excessive privileges")
	}

	const required = `SELECT
		has_table_privilege(current_user, 'content_posts', 'SELECT')
		AND has_table_privilege(current_user, 'content_post_media', 'SELECT')
		AND has_function_privilege(current_user, 'public.content_set_draft_media(uuid,uuid,bigint,uuid[])', 'EXECUTE')
		AND has_function_privilege(current_user, 'public.content_publish_post_duration(uuid,uuid,bigint,text,bigint)', 'EXECUTE')
		AND has_function_privilege(current_user, 'public.content_change_author_removal(uuid,uuid,bigint,boolean)', 'EXECUTE')
		AND has_table_privilege(current_user, 'content_draft_requests', 'SELECT')
		AND has_table_privilege(current_user, 'content_author_purges', 'SELECT')
		AND has_table_privilege(current_user, 'content_draft_requests', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'id', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'author_id', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'media_kind', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'title', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'description', 'INSERT')
		AND NOT has_column_privilege(current_user, 'content_posts', 'title', 'UPDATE')
        AND NOT has_column_privilege(current_user, 'content_posts', 'description', 'UPDATE')
        AND NOT has_column_privilege(current_user, 'content_posts', 'revision', 'UPDATE')
        AND has_function_privilege(current_user, 'public.content_edit_post(uuid,uuid,bigint,text,text,text)', 'EXECUTE')`
	var sufficient bool

	if err := db.QueryRowContext(ctx, required).Scan(&sufficient); err != nil {
		return fmt.Errorf("check required content runtime privileges: %w", err)
	}

	if !sufficient {
		return errors.New("content runtime database role is missing required privileges")
	}

	return nil
}

// Cleanup may delete content, but cannot insert or publish posts.
func validatePurgePrivileges(ctx context.Context, db *sql.DB) error {
	if err := validateOutboxProtection(ctx, db); err != nil {
		return err
	}
	if err := validateReactionPrivileges(ctx, db, false); err != nil {
		return err
	}

	const query = `SELECT
        COALESCE((SELECT rolsuper FROM pg_roles WHERE rolname=current_user), true)
        OR EXISTS (SELECT 1 FROM pg_class WHERE oid=ANY(ARRAY['content_posts'::regclass, 'content_post_media'::regclass, 'content_draft_requests'::regclass, 'content_author_purges'::regclass]) AND pg_has_role(current_user, relowner, 'MEMBER'))
        OR has_table_privilege(current_user, 'content_posts', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_post_media', 'TRUNCATE')
        OR has_function_privilege(current_user, 'public.content_edit_post(uuid,uuid,bigint,text,text,text)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_set_draft_media(uuid,uuid,bigint,uuid[])', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_publish_private(uuid,uuid,bigint)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_publish_post_duration(uuid,uuid,bigint,text,bigint)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_publish_post(uuid,uuid,bigint,text)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_change_author_removal(uuid,uuid,bigint,boolean)', 'EXECUTE')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_posts', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_post_media', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRIGGER')
        OR has_any_column_privilege(current_user, 'content_posts', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'hidden_by_case', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'hidden_by_case', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'status', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'visibility', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'author_removed_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'video_duration_ms', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'video_duration_ms', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'published_edition', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_edition', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'author_id', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'id', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'media_kind', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'title', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'description', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'revision', 'UPDATE')
        OR has_table_privilege(current_user, 'content_post_media', 'DELETE')
        OR has_any_column_privilege(current_user, 'content_post_media', 'INSERT')
        OR has_any_column_privilege(current_user, 'content_post_media', 'UPDATE')
        OR has_any_column_privilege(current_user, 'content_draft_requests', 'INSERT')
        OR has_any_column_privilege(current_user, 'content_draft_requests', 'UPDATE')
        OR has_column_privilege(current_user, 'content_author_purges', 'started_at', 'INSERT')
        OR has_any_column_privilege(current_user, 'content_author_purges', 'UPDATE')`

	var excessive bool

	if err := db.QueryRowContext(ctx, query).Scan(&excessive); err != nil {
		return fmt.Errorf("check content purge privileges: %w", err)
	}

	if excessive {
		return errors.New("content purge database role has excessive privileges")
	}

	const required = `SELECT
		has_table_privilege(current_user, 'content_posts', 'SELECT')
		AND has_table_privilege(current_user, 'content_post_media', 'SELECT')
		AND has_table_privilege(current_user, 'content_draft_requests', 'SELECT')
		AND has_table_privilege(current_user, 'content_author_purges', 'SELECT')
		AND has_table_privilege(current_user, 'content_posts', 'DELETE')
		AND has_table_privilege(current_user, 'content_draft_requests', 'DELETE')
		AND has_column_privilege(current_user, 'content_posts', 'created_at', 'UPDATE')
		AND has_table_privilege(current_user, 'content_author_purges', 'DELETE')
		AND has_column_privilege(current_user, 'content_author_purges', 'author_id', 'INSERT')`
	var sufficient bool

	if err := db.QueryRowContext(ctx, required).Scan(&sufficient); err != nil {
		return fmt.Errorf("check required content purge privileges: %w", err)
	}

	if !sufficient {
		return errors.New("content purge database role is missing required privileges")
	}

	return nil
}

func validateReactionPrivileges(ctx context.Context, db *sql.DB, runtime bool) error {
	const query = `SELECT
		NOT EXISTS (
			SELECT 1 FROM pg_class c
			WHERE c.oid = ANY(ARRAY['public.content_post_likes'::regclass,
				'public.content_post_favorites'::regclass, 'public.content_post_statistics'::regclass,
				'public.content_post_view_receipts'::regclass, 'public.content_comments'::regclass])
			AND (c.relrowsecurity OR pg_has_role(current_user, c.relowner, 'MEMBER')
				OR has_any_column_privilege(current_user, c.oid, 'INSERT,UPDATE')
				OR has_table_privilege(current_user, c.oid, 'DELETE,TRUNCATE,TRIGGER')
				OR ($1 AND c.oid <> 'public.content_post_view_receipts'::regclass
					AND NOT has_table_privilege(current_user, c.oid, 'SELECT'))
				OR (c.oid = 'public.content_post_view_receipts'::regclass
					AND has_any_column_privilege(current_user, c.oid, 'SELECT')))
		)
		AND NOT EXISTS (
            SELECT 1 FROM pg_class c WHERE c.oid IN (
                'public.content_ad_campaigns'::regclass, 'public.content_ad_deliveries'::regclass, 'public.content_ad_campaign_events'::regclass, 'public.content_reports'::regclass, 'public.content_moderation_events'::regclass, 'public.content_moderation_appeals'::regclass, 'public.content_case_owners'::regclass, 'public.content_points_accounts'::regclass,
                'public.content_points_ledger'::regclass, 'public.content_points_policies'::regclass, 'public.content_points_deductions'::regclass, 'public.content_points_warnings'::regclass, 'public.content_points_bans'::regclass
            ) AND (c.relrowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER')
                OR has_any_column_privilege(current_user,c.oid,'SELECT,INSERT,UPDATE')
                OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER'))
        )
        AND EXISTS (
            SELECT 1 FROM pg_class c WHERE c.oid='public.content_post_history'::regclass
                AND NOT c.relrowsecurity AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
                AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE')
                AND NOT has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER')
                AND has_table_privilege(current_user,c.oid,'SELECT')=$1
        )
        AND EXISTS (
            SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.content_posts'::regclass
                AND t.tgname='content_record_post_history' AND t.tgenabled IN ('O','A')
                AND t.tgfoid='public.content_record_post_history()'::regprocedure
        )
        AND EXISTS (
            SELECT 1 FROM pg_class c WHERE c.oid='public.content_video_covers'::regclass
                AND NOT c.relrowsecurity AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
                AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE')
                AND NOT has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER')
                AND has_table_privilege(current_user,c.oid,'SELECT')=$1
        )
        AND has_function_privilege(current_user, 'public.content_set_video_cover(uuid,uuid,bigint,uuid,text)', 'EXECUTE') = $1
        AND NOT has_function_privilege(current_user, 'public.content_reward_public_views(uuid,integer)', 'EXECUTE')
        AND has_function_privilege(current_user, 'public.content_apply_profile_points(uuid,uuid,text,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_revoke_media_attachment(uuid,uuid)', 'EXECUTE') = $1
        AND NOT has_any_column_privilege(current_user, 'public.content_revoked_media', 'SELECT,INSERT,UPDATE')
        AND NOT has_table_privilege(current_user, 'public.content_revoked_media', 'DELETE,TRUNCATE,TRIGGER')
        AND NOT has_function_privilege(current_user, 'public.content_deduct_moderation_points(uuid,uuid,text,text)', 'EXECUTE')
        AND NOT has_function_privilege(current_user, 'public.content_refund_moderation_points(uuid)', 'EXECUTE')
        AND NOT has_any_column_privilege(current_user, 'public.content_profile_points_events', 'SELECT,INSERT,UPDATE')
        AND NOT has_table_privilege(current_user, 'public.content_profile_points_events', 'DELETE,TRUNCATE,TRIGGER')
        AND NOT has_function_privilege(current_user, 'public.content_reward_ad_impressions()', 'EXECUTE')
        AND has_function_privilege(current_user, 'public.content_owner_point_notices(uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_active_points_ban(uuid)', 'EXECUTE') = $1
        AND EXISTS (
            SELECT 1 FROM pg_class c WHERE c.oid='public.content_scheduled_posts'::regclass
                AND NOT c.relrowsecurity AND NOT pg_has_role(current_user,c.relowner,'MEMBER')
                AND NOT has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE')
                AND NOT has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER')
                AND has_table_privilege(current_user,c.oid,'SELECT')=$1
        )
        AND has_function_privilege(current_user, 'public.content_schedule_post(uuid,uuid,bigint,timestamptz,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_claim_scheduled_post()', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_publish_scheduled_post(uuid,uuid,uuid,bigint)', 'EXECUTE') = $1
        AND (NOT has_function_privilege(current_user, 'public.content_publish_scheduled_post(uuid,uuid,uuid)', 'EXECUTE') OR $1)
        AND has_function_privilege(current_user, 'public.content_ensure_recommendations()', 'EXECUTE') = $1
        AND NOT EXISTS (
            SELECT 1 FROM pg_class c WHERE c.oid IN ('public.content_recommendation_snapshots'::regclass,'public.content_recommendations'::regclass)
              AND (c.relrowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER')
                OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE')
                OR has_table_privilege(current_user,c.oid,'DELETE,TRUNCATE,TRIGGER'))
        )
        AND has_table_privilege(current_user,'public.content_recommendations','SELECT')=$1
        AND has_function_privilege(current_user, 'public.content_owner_points(uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_purge_points(uuid)', 'EXECUTE') <> $1
        AND has_function_privilege(current_user, 'public.content_owner_moderation(uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_submit_appeal(uuid,uuid,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_appeal_queue(uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_appeal_detail(uuid,uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_review_appeal(uuid,uuid,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_moderation_queue(uuid,boolean,timestamptz,uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_moderation_case_detail(uuid,uuid,bigint)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_case_media_access(uuid,uuid,uuid,uuid)', 'EXECUTE') = $1
        AND NOT has_function_privilege(current_user, 'public.content_reviewable_post(uuid,uuid)', 'EXECUTE')
        AND NOT has_function_privilege(current_user, 'public.content_can_read_pending_appeal(uuid,uuid)', 'EXECUTE')
        AND has_function_privilege(current_user, 'public.content_moderate_report(uuid,uuid,uuid,bigint,text,text,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_submit_report(uuid,uuid,uuid,uuid,text,boolean)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_submit_anonymous_safety_report(uuid,text)', 'EXECUTE') = $1
        AND NOT has_any_column_privilege(current_user, 'public.content_safety_report_budget', 'SELECT,INSERT,UPDATE')
        AND NOT has_table_privilege(current_user, 'public.content_safety_report_budget', 'DELETE,TRUNCATE,TRIGGER')
        AND has_function_privilege(current_user, 'public.content_own_report(uuid,uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_purge_reporter(uuid)', 'EXECUTE') <> $1
        AND NOT has_function_privilege(current_user, 'public.content_erase_reporter(uuid)', 'EXECUTE')
        AND has_function_privilege(current_user, 'public.content_select_ad(uuid,uuid,text)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_report_ad_impression(uuid,uuid)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_ad_campaign_list(uuid,integer)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_ad_campaign_daily_report(uuid,date,date)', 'EXECUTE') = $1
        AND NOT has_function_privilege(current_user, 'public.content_record_ad_daily_stats()', 'EXECUTE')
        AND NOT has_any_column_privilege(current_user, 'public.content_ad_campaign_daily_stats', 'SELECT,INSERT,UPDATE')
        AND NOT has_table_privilege(current_user, 'public.content_ad_campaign_daily_stats', 'DELETE,TRUNCATE,TRIGGER')
        AND has_function_privilege(current_user, 'public.content_ad_campaign_put(uuid,uuid,bigint,text,text,text,timestamptz,timestamptz,boolean,bigint)', 'EXECUTE') = $1
        AND has_function_privilege(current_user, 'public.content_purge_ad_deliveries(uuid)', 'EXECUTE') <> $1
        AND has_function_privilege(current_user, 'public.content_write_comment(uuid,uuid,uuid,text)', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_purge_comments(uuid)', 'EXECUTE') <> $1
		AND has_function_privilege(current_user, 'public.content_set_reaction(uuid,uuid,uuid,text,boolean)', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_purge_viewer_reactions(uuid)', 'EXECUTE') <> $1
		AND has_function_privilege(current_user, 'public.content_count_post_view(uuid,uuid,uuid,integer)', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_popular_for_playback(uuid)', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_prune_view_receipts()', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_purge_view_receipts(uuid)', 'EXECUTE') <> $1`

	var valid bool
	if err := db.QueryRowContext(ctx, query, runtime).Scan(&valid); err != nil {
		return fmt.Errorf("check reaction privileges: %w", err)
	}
	if !valid {
		return errors.New("invalid reaction privileges for content database role")
	}

	return nil
}

// Application roles must not alter the outbox or bypass its recording triggers.
func validateOutboxProtection(ctx context.Context, db *sql.DB) error {
	const query = `SELECT
		COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user), true)
		OR pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid='content_search_events'::regclass), 'MEMBER')
		OR (SELECT relrowsecurity FROM pg_class WHERE oid='content_search_events'::regclass)
		OR has_schema_privilege(current_user, 'public', 'CREATE')
		OR has_parameter_privilege(current_user, 'session_replication_role', 'SET')
		OR has_table_privilege(current_user, 'content_search_events', 'TRUNCATE')
		OR has_table_privilege(current_user, 'content_search_events', 'TRIGGER')
		OR has_table_privilege(current_user, 'content_search_events', 'DELETE')
		OR has_any_column_privilege(current_user, 'content_search_events', 'INSERT')
		OR has_any_column_privilege(current_user, 'content_search_events', 'UPDATE')
		OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_class c ON c.oid='content_search_events'::regclass
			WHERE p.oid='content_record_search_event()'::regprocedure AND p.prosecdef AND p.proowner=c.relowner
			AND p.proconfig @> ARRAY['search_path=pg_catalog, public'])
		OR (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid='content_posts'::regclass
			AND t.tgname IN ('content_search_insert_delete', 'content_search_update', 'content_search_visibility')
			AND t.tgfoid='content_record_search_event()'::regprocedure AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal) <> 3`

	var invalid bool

	if err := db.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
		return fmt.Errorf("check content outbox protection: %w", err)
	}

	if invalid {
		return errors.New("invalid content outbox protection")
	}

	return nil
}
