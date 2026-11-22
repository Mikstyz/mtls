package main

import (
	"context"
	"database/sql"
	"errors"
)

// Keep the role used by a production instance unable to confirm test orders.
func validateSalesPrivileges(ctx context.Context, db *sql.DB, enabled, purger bool) error {
	const query = `SELECT NOT EXISTS (
		SELECT 1 FROM pg_class c WHERE c.oid IN ('public.content_test_offers'::regclass,'public.content_test_orders'::regclass)
	AND (c.relrowsecurity OR pg_has_role(current_user,c.relowner,'MEMBER')
 OR has_table_privilege(current_user,c.oid,'TRUNCATE,DELETE,TRIGGER')
 OR has_any_column_privilege(current_user,c.oid,'INSERT,UPDATE'))
	) AND NOT has_any_column_privilege(current_user,'public.content_test_orders','SELECT')
AND CASE WHEN $1 THEN has_table_privilege(current_user,'public.content_test_offers','SELECT')
         ELSE NOT has_any_column_privilege(current_user,'public.content_test_offers','SELECT') END
	AND has_function_privilege(current_user,'public.content_test_entitled(uuid,bigint,uuid)','EXECUTE')<>$2
	AND has_function_privilege(current_user, 'public.content_set_reaction(uuid,uuid,uuid,text,boolean,boolean)', 'EXECUTE') = $1
	AND has_function_privilege(current_user, 'public.content_write_comment(uuid,uuid,uuid,text,boolean)', 'EXECUTE') = $1
	AND has_function_privilege(current_user, 'public.content_count_post_view(uuid,uuid,uuid,integer,boolean)', 'EXECUTE') = $1
	AND has_function_privilege(current_user,'public.content_test_offer(uuid,uuid,bigint,bigint,text)','EXECUTE')=$1
	AND has_function_privilege(current_user,'public.content_test_purchase(uuid,uuid,uuid,bigint)','EXECUTE')=$1
	AND has_function_privilege(current_user,'public.content_test_revoke(uuid,uuid)','EXECUTE')=$1
	AND has_function_privilege(current_user,'public.content_test_receipt(uuid,uuid)','EXECUTE')=$1
	AND has_function_privilege(current_user,'public.content_test_receipts(uuid,timestamptz,uuid,integer)','EXECUTE')=$1
	AND has_function_privilege(current_user,'public.content_purge_test_orders(uuid)','EXECUTE')=$2`
	var valid bool
	if err := db.QueryRowContext(ctx, query, enabled, purger).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid database permissions for configured sales mode")
	}
	return nil
}
