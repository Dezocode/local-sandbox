CREATE TABLE `apple_native_grants` (
	`schema_version` integer NOT NULL,
	`grant_hash` text PRIMARY KEY NOT NULL,
	`authorization_code_hash` text NOT NULL,
	`session_hash` text NOT NULL,
	`owner_id` text NOT NULL,
	`principal_id` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`owner_binding` text NOT NULL,
	`encrypted_credentials` text NOT NULL,
	`created_at` integer NOT NULL,
	`last_validated_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`revocation_pending_at` integer
);--> statement-breakpoint
CREATE UNIQUE INDEX `apple_native_grants_authorization_code_unique` ON `apple_native_grants` (`authorization_code_hash`);--> statement-breakpoint
CREATE UNIQUE INDEX `apple_native_grants_session_unique` ON `apple_native_grants` (`session_hash`);--> statement-breakpoint
CREATE INDEX `apple_native_grants_principal_idx` ON `apple_native_grants` (`owner_id`,`principal_id`,`grant_hash`);--> statement-breakpoint
CREATE INDEX `apple_native_grants_expiry_idx` ON `apple_native_grants` (`expires_at`,`grant_hash`);--> statement-breakpoint
CREATE TABLE `apple_native_authorization_code_claims` (
	`authorization_code_hash` text PRIMARY KEY NOT NULL,
	`claimed_at` integer NOT NULL,
	`expires_at` integer NOT NULL
);--> statement-breakpoint
CREATE INDEX `apple_native_authorization_code_claims_expiry_idx` ON `apple_native_authorization_code_claims` (`expires_at`,`authorization_code_hash`);--> statement-breakpoint
PRAGMA optimize;
