CREATE FUNCTION content_set_draft_media(
    draft_author UUID, draft_id UUID, expected_revision BIGINT, attachments UUID[]
) RETURNS BIGINT
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE
    active_revision BIGINT;
    current_attachments UUID[];
BEGIN
    IF attachments IS NULL OR cardinality(attachments) > 16
        OR EXISTS (SELECT 1 FROM unnest(attachments) AS item(id)
            GROUP BY id HAVING id IS NULL OR id = '00000000-0000-0000-0000-000000000000' OR count(*) > 1)
        OR expected_revision IS NULL OR expected_revision < 1 THEN
        RAISE EXCEPTION 'invalid draft attachments' USING ERRCODE = '22023';
    END IF;

    PERFORM pg_advisory_xact_lock(hashtextextended('content-author:' || draft_author::text, 0));

    SELECT revision INTO active_revision FROM public.content_posts
    WHERE id = draft_id AND author_id = draft_author AND status = 'draft' AND visibility = 'private'
        AND NOT EXISTS (SELECT 1 FROM public.content_author_purges WHERE author_id = draft_author)
    FOR UPDATE;
    IF NOT FOUND THEN RETURN -1; END IF;

    SELECT COALESCE(array_agg(media_id ORDER BY position), ARRAY[]::UUID[])
    INTO current_attachments FROM public.content_post_media WHERE post_id = draft_id;

    IF current_attachments = attachments AND active_revision IN (expected_revision, expected_revision + 1::numeric) THEN
        RETURN active_revision;
    END IF;

    IF active_revision <> expected_revision THEN RETURN 0; END IF;

    DELETE FROM public.content_post_media WHERE post_id = draft_id;
    INSERT INTO public.content_post_media (post_id, media_id, position)
        SELECT draft_id, item.id, (item.position - 1)::INTEGER
        FROM unnest(attachments) WITH ORDINALITY AS item(id, position);

    UPDATE public.content_posts SET revision = revision + 1 WHERE id = draft_id
        RETURNING revision INTO active_revision;
    RETURN active_revision;
END;
$$;

REVOKE ALL ON FUNCTION content_set_draft_media(UUID, UUID, BIGINT, UUID[]) FROM PUBLIC;
