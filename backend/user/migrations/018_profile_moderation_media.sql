CREATE FUNCTION user_profile_moderation_media_owner(actor UUID,target UUID,media UUID) RETURNS UUID
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public AS $$
    SELECT r.owner_id
    FROM public.user_profile_image_reports r
    JOIN public.users u ON u.id=r.owner_id
    JOIN public.media_permissions p ON p.media_id=r.media_id AND p.owner_id=r.owner_id
    LEFT JOIN public.user_profile_image_decisions d ON d.case_id=r.case_id
    LEFT JOIN public.user_profile_image_appeals a ON a.case_id=r.case_id
    WHERE r.case_id=target AND r.media_id=media
        AND r.owner_id<>actor AND r.reporter_id IS DISTINCT FROM actor
        AND EXISTS (SELECT 1 FROM public.users WHERE id=actor)
        AND p.ready AND p.revoked_at IS NULL AND p.media_kind='photo'
        AND (r.status='pending' OR (
            r.status='resolved' AND d.action='remove' AND d.actor_id<>actor
            AND a.case_id IS NOT NULL AND a.outcome IS NULL
        ))
$$;

REVOKE ALL ON FUNCTION user_profile_moderation_media_owner(UUID,UUID,UUID) FROM PUBLIC;
