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
        OR has_column_privilege(current_user, 'content_posts', 'status', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'created_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'author_removed_at', 'UPDATE')
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
		AND has_function_privilege(current_user, 'public.content_publish_post(uuid,uuid,bigint,text)', 'EXECUTE')
		AND has_function_privilege(current_user, 'public.content_change_author_removal(uuid,uuid,bigint,boolean)', 'EXECUTE')
		AND has_table_privilege(current_user, 'content_draft_requests', 'SELECT')
		AND has_table_privilege(current_user, 'content_author_purges', 'SELECT')
		AND has_table_privilege(current_user, 'content_draft_requests', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'id', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'author_id', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'media_kind', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'title', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'description', 'INSERT')
		AND has_column_privilege(current_user, 'content_posts', 'title', 'UPDATE')
		AND has_column_privilege(current_user, 'content_posts', 'description', 'UPDATE')
		AND has_column_privilege(current_user, 'content_posts', 'revision', 'UPDATE')`
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
        OR has_function_privilege(current_user, 'public.content_set_draft_media(uuid,uuid,bigint,uuid[])', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_publish_private(uuid,uuid,bigint)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_publish_post(uuid,uuid,bigint,text)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.content_change_author_removal(uuid,uuid,bigint,boolean)', 'EXECUTE')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRUNCATE')
        OR has_table_privilege(current_user, 'content_posts', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_post_media', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_draft_requests', 'TRIGGER')
        OR has_table_privilege(current_user, 'content_author_purges', 'TRIGGER')
        OR has_any_column_privilege(current_user, 'content_posts', 'INSERT')
        OR has_column_privilege(current_user, 'content_posts', 'status', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'visibility', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'published_at', 'UPDATE')
        OR has_column_privilege(current_user, 'content_posts', 'author_removed_at', 'UPDATE')
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
				'public.content_post_view_receipts'::regclass])
			AND (c.relrowsecurity OR pg_has_role(current_user, c.relowner, 'MEMBER')
				OR has_any_column_privilege(current_user, c.oid, 'INSERT,UPDATE')
				OR has_table_privilege(current_user, c.oid, 'DELETE,TRUNCATE,TRIGGER')
				OR ($1 AND c.oid <> 'public.content_post_view_receipts'::regclass
					AND NOT has_table_privilege(current_user, c.oid, 'SELECT'))
				OR (c.oid = 'public.content_post_view_receipts'::regclass
					AND has_any_column_privilege(current_user, c.oid, 'SELECT')))
		)
		AND has_function_privilege(current_user, 'public.content_set_reaction(uuid,uuid,uuid,text,boolean)', 'EXECUTE') = $1
		AND has_function_privilege(current_user, 'public.content_purge_viewer_reactions(uuid)', 'EXECUTE') <> $1
		AND has_function_privilege(current_user, 'public.content_count_post_view(uuid,uuid,uuid,integer)', 'EXECUTE') = $1
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
			AND t.tgname IN ('content_search_insert_delete', 'content_search_update')
			AND t.tgfoid='content_record_search_event()'::regprocedure AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal) <> 2`

	var invalid bool

	if err := db.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
		return fmt.Errorf("check content outbox protection: %w", err)
	}

	if invalid {
		return errors.New("invalid content outbox protection")
	}

	return nil
}
