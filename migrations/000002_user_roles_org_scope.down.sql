ALTER TABLE user_roles
    DROP CONSTRAINT user_roles_user_org_fkey,
    DROP CONSTRAINT user_roles_role_org_fkey;

ALTER TABLE user_roles
    DROP COLUMN org_id;

ALTER TABLE user_roles
    ADD CONSTRAINT user_roles_user_id_fkey
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    ADD CONSTRAINT user_roles_role_id_fkey
        FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE;

ALTER TABLE roles
    DROP CONSTRAINT roles_id_org_id_key;

ALTER TABLE users
    DROP CONSTRAINT users_id_org_id_key;
