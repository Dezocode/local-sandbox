PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_apple_native_sessions` (
	`schema_version` integer NOT NULL,
	`identity_token_hash` text PRIMARY KEY NOT NULL,
	`session_hash` text NOT NULL,
	`owner_id` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`activation_state` text DEFAULT 'pending' NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`identity_token_expires_at` integer NOT NULL,
	`revoked_at` integer,
	CONSTRAINT "apple_native_sessions_activation_state_check" CHECK("__new_apple_native_sessions"."activation_state" in ('pending','active'))
);
--> statement-breakpoint
INSERT INTO `__new_apple_native_sessions`("schema_version", "identity_token_hash", "session_hash", "owner_id", "apple_subject_hash", "activation_state", "created_at", "expires_at", "identity_token_expires_at", "revoked_at") SELECT "schema_version", "identity_token_hash", "session_hash", "owner_id", "apple_subject_hash", 'active', "created_at", "expires_at", "identity_token_expires_at", "revoked_at" FROM `apple_native_sessions`;--> statement-breakpoint
DROP TABLE `apple_native_sessions`;--> statement-breakpoint
ALTER TABLE `__new_apple_native_sessions` RENAME TO `apple_native_sessions`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE UNIQUE INDEX `apple_native_sessions_session_hash_unique` ON `apple_native_sessions` (`session_hash`);--> statement-breakpoint
CREATE INDEX `apple_native_sessions_expiry_idx` ON `apple_native_sessions` (`expires_at`,`identity_token_hash`);
