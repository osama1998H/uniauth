INSERT INTO permissions (name, description) VALUES
    ('organizations:read',  'Read organization profile data'),
    ('organizations:write', 'Update organization profile data')
ON CONFLICT (name) DO NOTHING;
