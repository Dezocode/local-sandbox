DELETE FROM `apple_auth_flows`;--> statement-breakpoint
ALTER TABLE `apple_auth_flows` ADD `purpose` text NOT NULL;--> statement-breakpoint
ALTER TABLE `apple_auth_flows` ADD `owner_id` text;--> statement-breakpoint
ALTER TABLE `apple_auth_sessions` ADD `owner_id` text;--> statement-breakpoint
UPDATE `apple_auth_sessions`
SET `owner_id` = (
	SELECT `owner_id`
	FROM `apple_identity_links`
	WHERE `apple_identity_links`.`apple_subject_hash` = `apple_auth_sessions`.`apple_subject_hash`
);--> statement-breakpoint
DELETE FROM `apple_auth_sessions` WHERE `owner_id` IS NULL;--> statement-breakpoint
CREATE TABLE `__new_apple_auth_sessions` (
	`schema_version` integer NOT NULL,
	`session_hash` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`owner_binding` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`encrypted_credentials` text NOT NULL,
	`created_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	`last_validated_at` integer NOT NULL,
	`revoked_at` integer
);--> statement-breakpoint
INSERT INTO `__new_apple_auth_sessions`(
	`schema_version`,`session_hash`,`owner_id`,`owner_binding`,`apple_subject_hash`,
	`encrypted_credentials`,`created_at`,`expires_at`,`last_validated_at`,`revoked_at`
)
SELECT
	`schema_version`,`session_hash`,`owner_id`,`owner_binding`,`apple_subject_hash`,
	`encrypted_credentials`,`created_at`,`expires_at`,`last_validated_at`,`revoked_at`
FROM `apple_auth_sessions`;--> statement-breakpoint
DROP TABLE `apple_auth_sessions`;--> statement-breakpoint
ALTER TABLE `__new_apple_auth_sessions` RENAME TO `apple_auth_sessions`;
