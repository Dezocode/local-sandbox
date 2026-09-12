CREATE TABLE `origin_auth_flows` (
	`state_hash` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`return_to` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`consumed_at` integer
);
--> statement-breakpoint
CREATE TABLE `origin_auth_receipts` (
	`receipt_id` text PRIMARY KEY NOT NULL,
	`expires_at` integer NOT NULL,
	`claimed_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `origin_installations` (
	`installation_id` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`namespace_id` text NOT NULL,
	`created_at` integer NOT NULL,
	`updated_at` integer NOT NULL
);
