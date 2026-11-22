package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ValidateQuotaRole checks the database role attached to this store.
func (s *Store) ValidateQuotaRole(ctx context.Context) error {
	if s == nil {
		return ErrInvalid
	}

	return ValidateQuotaRole(ctx, s.db)
}

// ValidateQuotaRole must succeed before an upload service accepts traffic.
// It protects accounting from untrusted SQL privileges and disabled triggers.
func ValidateQuotaRole(ctx context.Context, db *sql.DB) error {
	if ctx == nil || db == nil {
		return ErrInvalid
	}

	const query = `SELECT
		COALESCE((SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user), TRUE)
		OR has_schema_privilege(current_user, 'public', 'CREATE')
		OR has_parameter_privilege(current_user, 'session_replication_role', 'SET')
		OR EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = ANY(ARRAY[
			'public.media_storage_usage'::regclass, 'public.media_assets'::regclass, 'public.media_uploads'::regclass, 'public.media_purged_owners'::regclass
		]) AND (c.relrowsecurity OR pg_has_role(current_user, c.relowner, 'MEMBER')))
		OR has_function_privilege(current_user, 'public.media_purge_owner_batch(uuid)', 'EXECUTE')
        OR has_function_privilege(current_user, 'public.media_expire_reservations(integer)', 'EXECUTE')
        OR has_table_privilege(current_user, 'public.media_purged_owners', 'DELETE, TRUNCATE, TRIGGER')
        OR has_any_column_privilege(current_user, 'public.media_purged_owners', 'INSERT, UPDATE')
        OR NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid = 'public.media_assets'::regclass
            AND tgname = 'media_guard_owner_before_insert' AND tgenabled IN ('O','A')
            AND tgfoid='public.media_guard_purged_owner()'::regprocedure)
        OR has_table_privilege(current_user, 'public.media_storage_usage', 'TRUNCATE')
		OR has_table_privilege(current_user, 'public.media_storage_usage', 'TRIGGER')
		OR has_table_privilege(current_user, 'public.media_storage_usage', 'DELETE')
		OR has_any_column_privilege(current_user, 'public.media_storage_usage', 'INSERT')
		OR has_any_column_privilege(current_user, 'public.media_storage_usage', 'UPDATE')
		OR NOT has_table_privilege(current_user, 'public.media_storage_usage', 'SELECT')
		OR NOT has_function_privilege(current_user, 'public.media_lock_usage()', 'EXECUTE')
		OR NOT has_function_privilege(current_user, 'public.media_upload_cover_frames(uuid,uuid)', 'EXECUTE')
		OR NOT has_function_privilege(current_user, 'public.media_begin_upload(uuid,uuid,bigint,bytea,text)', 'EXECUTE')
        OR has_column_privilege(current_user, 'public.media_uploads', 'transfer_mode', 'UPDATE')
		OR has_column_privilege(current_user, 'public.media_assets', 'files_removed_at', 'UPDATE')
		OR has_table_privilege(current_user, 'public.media_assets', 'TRUNCATE')
		OR has_table_privilege(current_user, 'public.media_assets', 'TRIGGER')
		OR has_table_privilege(current_user, 'public.media_uploads', 'TRUNCATE')
		OR has_table_privilege(current_user, 'public.media_uploads', 'TRIGGER')
		OR (SELECT count(*) FROM pg_proc p JOIN pg_class c ON c.oid = 'public.media_storage_usage'::regclass
			WHERE p.oid = ANY(ARRAY['public.media_count_asset()'::regprocedure, 'public.media_count_upload()'::regprocedure, 'public.media_lock_usage()'::regprocedure, 'public.media_release_removed_usage()'::regprocedure])
				AND p.prosecdef AND p.proowner = c.relowner AND p.proconfig @> ARRAY['search_path=pg_catalog, public']) <> 4
		OR (SELECT count(*) FROM pg_trigger t WHERE NOT t.tgisinternal AND t.tgenabled IN ('O','A')
			AND ((t.tgrelid = 'public.media_assets'::regclass AND t.tgname = 'media_usage_asset_insert_delete'
				AND t.tgfoid = 'public.media_count_asset()'::regprocedure)
 OR (t.tgrelid = 'public.media_assets'::regclass AND t.tgname = 'media_usage_release_removed'
 AND t.tgfoid = 'public.media_release_removed_usage()'::regprocedure)
			OR (t.tgrelid = 'public.media_uploads'::regclass AND t.tgname IN ('media_usage_upload_insert_delete', 'media_usage_upload_size_update')
				AND t.tgfoid = 'public.media_count_upload()'::regprocedure))) <> 4
		OR NOT EXISTS (SELECT 1 FROM public.media_storage_usage WHERE id)`

	var invalid bool

	if err := db.QueryRowContext(ctx, query).Scan(&invalid); err != nil {
		return fmt.Errorf("check media quota protection: %w", err)
	}

	if invalid {
		return errors.New("invalid media quota database privileges or accounting triggers")
	}

	return nil
}
