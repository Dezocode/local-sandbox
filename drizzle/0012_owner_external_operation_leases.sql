CREATE TABLE `apple_owner_external_operation_leases` (
	`lease_token` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`installation_id` text NOT NULL,
	`apple_subject_hash` text,
	`apple_principal_id` text,
	`claimed_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `apple_owner_external_operation_leases_identity_check`
		CHECK ((`apple_subject_hash` is null and `apple_principal_id` is null)
			or (`apple_subject_hash` is not null and `apple_principal_id` is not null))
);--> statement-breakpoint
CREATE INDEX `apple_owner_external_operation_leases_expiry_idx`
ON `apple_owner_external_operation_leases` (`expires_at`,`lease_token`);--> statement-breakpoint
CREATE INDEX `apple_owner_external_operation_leases_owner_principal_expiry_idx`
ON `apple_owner_external_operation_leases` (`owner_id`,`apple_principal_id`,`expires_at`);--> statement-breakpoint
PRAGMA optimize;
