ALTER TABLE `apple_identity_links` ADD `principal_id` text;--> statement-breakpoint
ALTER TABLE `apple_identity_links` ADD `principal_created_at` integer;--> statement-breakpoint
UPDATE `apple_identity_links`
SET `principal_id`=`apple_subject_hash`,`principal_created_at`=`created_at`
WHERE `principal_id` IS NULL OR `principal_created_at` IS NULL;--> statement-breakpoint
CREATE TRIGGER `apple_identity_links_principal_after_insert`
AFTER INSERT ON `apple_identity_links`
WHEN NEW.`principal_id` IS NULL OR NEW.`principal_created_at` IS NULL
BEGIN
	UPDATE `apple_identity_links`
	SET `principal_id`=COALESCE(NEW.`principal_id`,NEW.`apple_subject_hash`),
		`principal_created_at`=COALESCE(NEW.`principal_created_at`,NEW.`created_at`)
	WHERE `apple_subject_hash`=NEW.`apple_subject_hash`;
END;--> statement-breakpoint
CREATE INDEX `apple_identity_links_principal_idx` ON `apple_identity_links` (`owner_id`,`principal_id`,`apple_subject_hash`);--> statement-breakpoint
ALTER TABLE `apple_account_deletions` ADD `apple_principal_id` text;--> statement-breakpoint
UPDATE `apple_account_deletions`
SET `apple_principal_id`=COALESCE(
	(SELECT `principal_id` FROM `apple_identity_links`
	 WHERE `apple_identity_links`.`apple_subject_hash`=`apple_account_deletions`.`apple_subject_hash`
	   AND `apple_identity_links`.`owner_id`=`apple_account_deletions`.`owner_id`),
	`apple_subject_hash`
)
WHERE `apple_principal_id` IS NULL;--> statement-breakpoint
CREATE TRIGGER `apple_account_deletions_principal_after_insert`
AFTER INSERT ON `apple_account_deletions`
WHEN NEW.`apple_principal_id` IS NULL
BEGIN
	UPDATE `apple_account_deletions`
	SET `apple_principal_id`=COALESCE(
		(SELECT `principal_id` FROM `apple_identity_links`
		 WHERE `apple_identity_links`.`apple_subject_hash`=NEW.`apple_subject_hash`
		   AND `apple_identity_links`.`owner_id`=NEW.`owner_id`),
		NEW.`apple_subject_hash`
	)
	WHERE `deletion_key_hash`=NEW.`deletion_key_hash`;
END;--> statement-breakpoint
DROP INDEX `apple_account_deletions_linked_lease_idx`;--> statement-breakpoint
CREATE UNIQUE INDEX `apple_account_deletions_linked_lease_idx`
ON `apple_account_deletions` (`owner_id`,`apple_principal_id`)
WHERE `revocation_lease_token` is not null and `delete_owner_data`=0;--> statement-breakpoint
CREATE INDEX `apple_auth_flows_expiry_idx` ON `apple_auth_flows` (`expires_at`,`state_hash`);--> statement-breakpoint
CREATE INDEX `apple_auth_sessions_expiry_idx` ON `apple_auth_sessions` (`expires_at`,`session_hash`);--> statement-breakpoint
CREATE INDEX `apple_native_sessions_expiry_idx` ON `apple_native_sessions` (`expires_at`,`identity_token_hash`);--> statement-breakpoint
PRAGMA optimize;
