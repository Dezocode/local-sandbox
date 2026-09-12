CREATE TABLE `apple_account_deletions` (
	`deletion_key_hash` text PRIMARY KEY NOT NULL,
	`owner_binding` text NOT NULL,
	`owner_id` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`delete_owner_data` integer NOT NULL,
	`provider_credentials` text,
	`origin_connections` text,
	`revocation_lease_token` text,
	`revocation_lease_until` integer,
	`completion_fence_token` text,
	`started_at` integer NOT NULL,
	`completed_at` integer,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
CREATE INDEX `apple_account_deletions_subject_expiry_idx` ON `apple_account_deletions` (`apple_subject_hash`,`expires_at`);--> statement-breakpoint
CREATE INDEX `apple_account_deletions_owner_subject_expiry_idx` ON `apple_account_deletions` (`owner_id`,`apple_subject_hash`,`expires_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `apple_account_deletions_standalone_lease_idx` ON `apple_account_deletions` (`owner_id`) WHERE `revocation_lease_token` is not null and `delete_owner_data`=1;--> statement-breakpoint
CREATE UNIQUE INDEX `apple_account_deletions_linked_lease_idx` ON `apple_account_deletions` (`owner_id`,`apple_subject_hash`) WHERE `revocation_lease_token` is not null and `delete_owner_data`=0;--> statement-breakpoint
CREATE TABLE `apple_auth_notifications` (
	`notification_id_hash` text PRIMARY KEY NOT NULL,
	`event_type` text NOT NULL,
	`apple_subject_hash` text,
	`owner_id` text,
	`issued_at` integer NOT NULL,
	`event_time` integer,
	`origin_connections` text,
	`origin_unresolved_installation_ids` text,
	`processed_at` integer NOT NULL,
	`expires_at` integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE `apple_identity_links` ADD `email_forwarding_enabled` integer;--> statement-breakpoint
ALTER TABLE `apple_identity_links` ADD `email_state_updated_at` integer;
