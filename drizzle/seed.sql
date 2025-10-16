-- Seed data for local testing
-- Run this after migrations to populate demo data

-- Demo public client (no client_secret)
INSERT INTO `clients` (`client_id`, `client_secret`, `redirect_uri`, `token_endpoint_auth_method`, `name`, `created_at`)
VALUES (
	'demo-public-client',
	NULL,
	'http://localhost:3000/callback',
	'none',
	'Demo Public Client',
	unixepoch()
);

-- Demo confidential client (with client_secret)
INSERT INTO `clients` (`client_id`, `client_secret`, `redirect_uri`, `token_endpoint_auth_method`, `name`, `created_at`)
VALUES (
	'demo-confidential-client',
	'demo-secret-12345',
	'http://localhost:3000/callback',
	'client_secret_basic',
	'Demo Confidential Client',
	unixepoch()
);

-- Demo user
-- Username: demouser
-- Password: password123
-- SHA256: ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
INSERT INTO `users` (`id`, `username`, `pw_sha256`, `name`, `email`, `created_at`, `updated_at`)
VALUES (
	'demo-user-001',
	'demouser',
	'ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f',
	'Demo User',
	'demo@example.com',
	unixepoch(),
	unixepoch()
);

