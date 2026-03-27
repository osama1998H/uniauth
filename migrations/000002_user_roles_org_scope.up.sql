ALTER TABLE users
    ADD CONSTRAINT users_id_org_id_key UNIQUE (id, org_id);

ALTER TABLE roles
    ADD CONSTRAINT roles_id_org_id_key UNIQUE (id, org_id);

ALTER TABLE user_roles
    ADD COLUMN org_id UUID;

DELETE FROM user_roles ur
USING users u, roles r
WHERE ur.user_id = u.id
  AND ur.role_id = r.id
  AND u.org_id <> r.org_id;

UPDATE user_roles ur
SET org_id = u.org_id
FROM users u
WHERE ur.user_id = u.id;

ALTER TABLE user_roles
    ALTER COLUMN org_id SET NOT NULL;

ALTER TABLE user_roles
    DROP CONSTRAINT user_roles_user_id_fkey,
    DROP CONSTRAINT user_roles_role_id_fkey;

ALTER TABLE user_roles
    ADD CONSTRAINT user_roles_user_org_fkey
        FOREIGN KEY (user_id, org_id) REFERENCES users (id, org_id) ON DELETE CASCADE,
    ADD CONSTRAINT user_roles_role_org_fkey
        FOREIGN KEY (role_id, org_id) REFERENCES roles (id, org_id) ON DELETE CASCADE;
