ALTER TABLE users
    ADD COLUMN photo_quality TEXT NOT NULL DEFAULT 'auto' CHECK(photo_quality IN ('auto','original','reduced')),
    ADD COLUMN video_quality TEXT NOT NULL DEFAULT 'auto' CHECK(video_quality IN ('auto','original','reduced'));

ALTER TABLE deleted_users
    ADD COLUMN photo_quality TEXT NOT NULL DEFAULT 'auto' CHECK(photo_quality IN ('auto','original','reduced')),
    ADD COLUMN video_quality TEXT NOT NULL DEFAULT 'auto' CHECK(video_quality IN ('auto','original','reduced'));
