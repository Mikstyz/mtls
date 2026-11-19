package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

func validatePrivileges(ctx context.Context, db *sql.DB) error {
	const query = `SELECT
		COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user), true)
		OR pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid='content_search_events'::regclass), 'MEMBER')
		OR (SELECT relrowsecurity FROM pg_class WHERE oid='content_search_events'::regclass)
		OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_class c ON c.oid='content_search_events'::regclass
			WHERE p.oid='content_record_search_event()'::regprocedure AND p.prosecdef AND p.proowner=c.relowner
			AND p.proconfig @> ARRAY['search_path=pg_catalog, public'])
		OR (SELECT count(*) FROM pg_trigger t WHERE t.tgrelid='content_posts'::regclass
			AND t.tgname IN ('content_search_insert_delete', 'content_search_update')
			AND t.tgfoid='content_record_search_event()'::regprocedure AND t.tgenabled IN ('O','A') AND NOT t.tgisinternal) <> 2
		OR has_schema_privilege(current_user, 'public', 'CREATE')
		OR has_parameter_privilege(current_user, 'session_replication_role', 'SET')
		OR has_table_privilege(current_user, 'content_posts', 'TRUNCATE')
		OR has_table_privilege(current_user, 'content_posts', 'TRIGGER')
		OR has_any_column_privilege(current_user, 'content_posts', 'INSERT')
		OR has_any_column_privilege(current_user, 'content_posts', 'UPDATE')
		OR has_table_privilege(current_user, 'content_posts', 'DELETE')
		OR has_table_privilege(current_user, 'content_search_events', 'TRUNCATE')
		OR has_table_privilege(current_user, 'content_search_events', 'TRIGGER')
		OR has_any_column_privilege(current_user, 'content_search_events', 'INSERT')
		OR has_column_privilege(current_user, 'content_search_events', 'version', 'UPDATE')
		OR has_column_privilege(current_user, 'content_search_events', 'post_id', 'UPDATE')
		OR has_column_privilege(current_user, 'content_search_events', 'title', 'UPDATE')
		OR has_column_privilege(current_user, 'content_search_events', 'deleted', 'UPDATE')
		OR NOT has_table_privilege(current_user, 'content_search_events', 'SELECT')
		OR NOT has_table_privilege(current_user, 'content_search_events', 'DELETE')
		OR NOT has_column_privilege(current_user, 'content_search_events', 'lease_token', 'UPDATE')
		OR NOT has_column_privilege(current_user, 'content_search_events', 'lease_until', 'UPDATE')`

	var invalid bool

	if err := db.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
		return fmt.Errorf("check publisher privileges: %w", err)
	}

	if invalid {
		return errors.New("invalid publisher database privileges")
	}

	return nil
}
