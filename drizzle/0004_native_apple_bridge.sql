CREATE TABLE IF NOT EXISTS `apple_identity_links` (
	`apple_subject_hash` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE IF NOT EXISTS `apple_native_sessions` (
	`schema_version` integer NOT NULL,
	`identity_token_hash` text PRIMARY KEY NOT NULL,
	`session_hash` text NOT NULL,
	`owner_id` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`identity_token_expires_at` integer NOT NULL,
	`revoked_at` integer
);
--> statement-breakpoint
CREATE UNIQUE INDEX IF NOT EXISTS `apple_native_sessions_session_hash_unique` ON `apple_native_sessions` (`session_hash`);
