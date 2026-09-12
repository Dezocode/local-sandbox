CREATE TABLE `apple_auth_flows` (
	`schema_version` integer NOT NULL,
	`state_hash` text PRIMARY KEY NOT NULL,
	`nonce_hash` text NOT NULL,
	`browser_binding_hash` text NOT NULL,
	`owner_binding` text NOT NULL,
	`return_to` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`consumed_at` integer
);
--> statement-breakpoint
CREATE TABLE `apple_auth_sessions` (
	`schema_version` integer NOT NULL,
	`session_hash` text PRIMARY KEY NOT NULL,
	`owner_binding` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`encrypted_credentials` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_validated_at` integer NOT NULL,
	`revoked_at` integer
);
