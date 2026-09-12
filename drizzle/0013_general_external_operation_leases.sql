ALTER TABLE `workspaces` ADD COLUMN `file_clock` integer DEFAULT -1 NOT NULL
	CONSTRAINT `workspaces_file_clock_safe_check`
	CHECK (`file_clock` between -1 and 9007199254740991);--> statement-breakpoint
ALTER TABLE `workspaces` ADD COLUMN `file_clock_claim` text
	CONSTRAINT `workspaces_file_clock_claim_check`
	CHECK (`file_clock_claim` is null or (length(`file_clock_claim`)=43
		and `file_clock_claim` not glob '*[^A-Za-z0-9_-]*'));--> statement-breakpoint
CREATE TABLE `files_next` (
	`user_id` text NOT NULL,
	`path` text NOT NULL,
	`content` text NOT NULL,
	`version` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY (`user_id`,`path`),
	CONSTRAINT `files_version_safe_check`
		CHECK (`version` between 0 and 9007199254740991)
);--> statement-breakpoint
INSERT INTO `files_next` (`user_id`,`path`,`content`,`version`)
SELECT `user_id`,`path`,`content`,`version` FROM `files`;--> statement-breakpoint
DROP TABLE `files`;--> statement-breakpoint
ALTER TABLE `files_next` RENAME TO `files`;--> statement-breakpoint
UPDATE `workspaces` SET `file_clock`=COALESCE((
	SELECT MAX(`files`.`version`) FROM `files`
	WHERE `files`.`user_id`=`workspaces`.`user_id`
),-1);--> statement-breakpoint
ALTER TABLE `sync_workspaces` ADD COLUMN `incarnation` text DEFAULT '0000000000000000000000000000000000000000000000000000000000000000' NOT NULL
	CONSTRAINT `sync_workspaces_incarnation_check`
	CHECK (length(`incarnation`)=64 and `incarnation` not glob '*[^0-9a-f]*');--> statement-breakpoint
DROP TRIGGER `sync_records_workspace_revision_after_insert`;--> statement-breakpoint
DROP TRIGGER `sync_records_workspace_revision_after_update`;--> statement-breakpoint
CREATE TABLE `sync_workspaces_next` (
	`user_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`epoch` text NOT NULL,
	`incarnation` text NOT NULL,
	`recovery` text NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY (`user_id`,`workspace_id`),
	CONSTRAINT `sync_workspaces_incarnation_check`
		CHECK (length(`incarnation`)=64 and `incarnation` not glob '*[^0-9a-f]*'),
	CONSTRAINT `sync_workspaces_revision_safe_check`
		CHECK (`revision` between 0 and 9007199254740991)
);--> statement-breakpoint
INSERT INTO `sync_workspaces_next` (`user_id`,`workspace_id`,`epoch`,`incarnation`,`recovery`,`revision`,`created_at`,`updated_at`)
SELECT `user_id`,`workspace_id`,`epoch`,`incarnation`,`recovery`,`revision`,`created_at`,`updated_at`
FROM `sync_workspaces`;--> statement-breakpoint
DROP TABLE `sync_workspaces`;--> statement-breakpoint
ALTER TABLE `sync_workspaces_next` RENAME TO `sync_workspaces`;--> statement-breakpoint
CREATE TABLE `sync_records_next` (
	`user_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`record_id` text NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	`mutation_id` text NOT NULL,
	`envelope` text NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY (`user_id`,`workspace_id`,`record_id`),
	CONSTRAINT `sync_records_revision_safe_check`
		CHECK (`revision` between 0 and 9007199254740991)
);--> statement-breakpoint
INSERT INTO `sync_records_next` (`user_id`,`workspace_id`,`record_id`,`revision`,`mutation_id`,`envelope`,`updated_at`)
SELECT `user_id`,`workspace_id`,`record_id`,`revision`,`mutation_id`,`envelope`,`updated_at`
FROM `sync_records`;--> statement-breakpoint
DROP TABLE `sync_records`;--> statement-breakpoint
ALTER TABLE `sync_records_next` RENAME TO `sync_records`;--> statement-breakpoint
CREATE TRIGGER `sync_records_workspace_revision_after_insert`
AFTER INSERT ON `sync_records`
BEGIN
	UPDATE `sync_workspaces`
	SET `revision`=`revision`+1,`updated_at`=NEW.`updated_at`
	WHERE `user_id`=NEW.`user_id` AND `workspace_id`=NEW.`workspace_id`;
END;--> statement-breakpoint
CREATE TRIGGER `sync_records_workspace_revision_after_update`
AFTER UPDATE OF `revision`,`mutation_id`,`envelope` ON `sync_records`
BEGIN
	UPDATE `sync_workspaces`
	SET `revision`=`revision`+1,`updated_at`=NEW.`updated_at`
	WHERE `user_id`=NEW.`user_id` AND `workspace_id`=NEW.`workspace_id`;
END;--> statement-breakpoint
INSERT OR IGNORE INTO `workspaces` (`user_id`,`policy`,`completed`,`revision`,`file_clock`,`file_clock_claim`)
SELECT DISTINCT `user_id`,'{"batteryBudget":15,"batteryReserve":20,"memoryTarget":35,"maxSteps":6,"maxFailures":3,"contextChars":6000,"cloudAllowed":false,"notifications":true,"clipboardReadAllowed":false,"clipboardWriteAllowed":false,"provider":"local","localShortcut":"Agent Step - Local"}','[]',0,-1,NULL
FROM `sync_workspaces`;--> statement-breakpoint
CREATE TABLE `sync_workspace_epochs` (
	`user_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`epoch` text NOT NULL,
	`incarnation` text NOT NULL,
	`enrolled_at` text NOT NULL,
	PRIMARY KEY (`user_id`,`workspace_id`,`epoch`),
	FOREIGN KEY (`user_id`) REFERENCES `workspaces`(`user_id`) ON UPDATE no action ON DELETE cascade,
	CONSTRAINT `sync_workspace_epochs_workspace_check`
		CHECK (length(`workspace_id`)=32 and `workspace_id` not glob '*[^A-Za-z0-9_-]*'),
	CONSTRAINT `sync_workspace_epochs_epoch_check`
		CHECK (length(`epoch`) between 16 and 64 and `epoch` not glob '*[^A-Za-z0-9_-]*'),
	CONSTRAINT `sync_workspace_epochs_incarnation_check`
		CHECK (length(`incarnation`)=64 and `incarnation` not glob '*[^0-9a-f]*')
);--> statement-breakpoint
CREATE UNIQUE INDEX `sync_workspace_epochs_incarnation_unique`
ON `sync_workspace_epochs` (`user_id`,`workspace_id`,`incarnation`);--> statement-breakpoint
CREATE INDEX `sync_workspace_epochs_owner_idx`
ON `sync_workspace_epochs` (`user_id`,`workspace_id`);--> statement-breakpoint
INSERT INTO `sync_workspace_epochs` (`user_id`,`workspace_id`,`epoch`,`incarnation`,`enrolled_at`)
SELECT `user_id`,`workspace_id`,`epoch`,`incarnation`,`created_at`
FROM `sync_workspaces`;--> statement-breakpoint
CREATE TABLE `apple_owner_external_operation_leases_next` (
	`lease_token` text PRIMARY KEY NOT NULL,
	`owner_id` text NOT NULL,
	`operation_kind` text NOT NULL,
	`resource_id` text NOT NULL,
	`apple_subject_hash` text,
	`apple_principal_id` text,
	`claimed_at` integer NOT NULL,
	`expires_at` integer NOT NULL,
	CONSTRAINT `apple_owner_external_operation_leases_operation_check`
		CHECK (`operation_kind` in ('origin','github','apple-auth','origin-install') and length(`resource_id`) between 1 and 200),
	CONSTRAINT `apple_owner_external_operation_leases_identity_check`
		CHECK ((`apple_subject_hash` is null and `apple_principal_id` is null)
			or (`apple_subject_hash` is not null and `apple_principal_id` is not null))
);--> statement-breakpoint
INSERT INTO `apple_owner_external_operation_leases_next` (
	`lease_token`,`owner_id`,`operation_kind`,`resource_id`,
	`apple_subject_hash`,`apple_principal_id`,`claimed_at`,`expires_at`
)
SELECT `lease_token`,`owner_id`,'origin',`installation_id`,`apple_subject_hash`,
	`apple_principal_id`,`claimed_at`,`expires_at`
FROM `apple_owner_external_operation_leases`;--> statement-breakpoint
DROP TABLE `apple_owner_external_operation_leases`;--> statement-breakpoint
ALTER TABLE `apple_owner_external_operation_leases_next`
RENAME TO `apple_owner_external_operation_leases`;--> statement-breakpoint
CREATE INDEX `apple_owner_external_operation_leases_expiry_idx`
ON `apple_owner_external_operation_leases` (`expires_at`,`lease_token`);--> statement-breakpoint
CREATE INDEX `apple_owner_external_operation_leases_owner_principal_expiry_idx`
ON `apple_owner_external_operation_leases` (`owner_id`,`apple_principal_id`,`expires_at`);--> statement-breakpoint
CREATE UNIQUE INDEX `apple_owner_external_operation_leases_apple_auth_principal_idx`
ON `apple_owner_external_operation_leases` (`owner_id`,`apple_principal_id`)
WHERE `operation_kind`='apple-auth';--> statement-breakpoint
CREATE UNIQUE INDEX `apple_owner_external_operation_leases_origin_install_principal_idx`
ON `apple_owner_external_operation_leases` (`owner_id`,`apple_principal_id`)
WHERE `operation_kind`='origin-install';--> statement-breakpoint
CREATE UNIQUE INDEX `apple_owner_external_operation_leases_origin_resource_idx`
ON `apple_owner_external_operation_leases` (`resource_id`)
WHERE `operation_kind` in ('origin','origin-install');--> statement-breakpoint
CREATE UNIQUE INDEX `apple_owner_external_operation_leases_origin_install_owner_idx`
ON `apple_owner_external_operation_leases` (`owner_id`)
WHERE `operation_kind`='origin-install';--> statement-breakpoint
CREATE TABLE `apple_auth_possible_credentials` (
	`owner_id` text NOT NULL,
	`apple_principal_id` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	`attempt_token` text NOT NULL,
	`review_token` text NOT NULL,
	`credential_state` text DEFAULT 'prepared' NOT NULL,
	`marked_at` integer NOT NULL,
	PRIMARY KEY (`owner_id`,`apple_principal_id`),
	CONSTRAINT `apple_auth_possible_credentials_hash_check`
		CHECK (length(`apple_principal_id`)=43 and length(`apple_subject_hash`)=43
			and length(`attempt_token`)=43 and length(`review_token`)=43),
	CONSTRAINT `apple_auth_possible_credentials_state_check`
		CHECK (`credential_state` in ('prepared','possible'))
);--> statement-breakpoint
CREATE INDEX `apple_auth_possible_credentials_subject_idx`
ON `apple_auth_possible_credentials` (`owner_id`,`apple_subject_hash`);--> statement-breakpoint
CREATE TABLE `origin_possible_installations` (
	`owner_id` text NOT NULL,
	`scope_id` text NOT NULL,
	`apple_principal_id` text,
	`apple_subject_hash` text,
	`flow_token` text NOT NULL,
	`marked_at` integer NOT NULL,
	PRIMARY KEY (`owner_id`,`scope_id`),
	CONSTRAINT `origin_possible_installations_hash_check`
		CHECK (((`scope_id`='host' and `apple_principal_id` is null and `apple_subject_hash` is null)
			or (`scope_id`=`apple_principal_id` and length(`apple_principal_id`)=43 and length(`apple_subject_hash`)=43))
			and length(`flow_token`)=43)
);--> statement-breakpoint
CREATE INDEX `origin_possible_installations_subject_idx`
ON `origin_possible_installations` (`owner_id`,`apple_subject_hash`);--> statement-breakpoint
CREATE TABLE `origin_installation_receipt_fences` (
	`installation_id` text PRIMARY KEY NOT NULL,
	`issued_at_fence` integer NOT NULL,
	CONSTRAINT `origin_installation_receipt_fences_installation_check`
		CHECK ((substr(`installation_id`,1,2)='i_' and length(`installation_id`) between 10 and 102
				and substr(`installation_id`,3) not glob '*[^a-z0-9]*')
			or (substr(`installation_id`,1,5)='inst_' and length(`installation_id`) between 13 and 105
				and substr(`installation_id`,6) not glob '*[^a-z0-9]*')),
	CONSTRAINT `origin_installation_receipt_fences_time_check`
		CHECK (`issued_at_fence` between 0 and 9007199254740991)
);--> statement-breakpoint
CREATE TABLE `apple_auth_admission_cutover` (
	`singleton` integer PRIMARY KEY NOT NULL,
	`cutover_at` integer NOT NULL,
	CONSTRAINT `apple_auth_admission_cutover_singleton_check`
		CHECK (`singleton`=1),
	CONSTRAINT `apple_auth_admission_cutover_time_check`
		CHECK (`cutover_at`>=0)
);--> statement-breakpoint
INSERT INTO `apple_auth_admission_cutover` (`singleton`,`cutover_at`)
VALUES (1,unixepoch()+300);--> statement-breakpoint
INSERT INTO `apple_account_deletion_subjects` (`deletion_key_hash`,`apple_subject_hash`)
SELECT `deletion_key_hash`,`apple_subject_hash`
FROM `apple_account_deletions`
WHERE 1=1
ON CONFLICT(`deletion_key_hash`,`apple_subject_hash`) DO NOTHING;--> statement-breakpoint
INSERT INTO `apple_account_deletion_subjects` (`deletion_key_hash`,`apple_subject_hash`)
SELECT deletion.`deletion_key_hash`,identity.`apple_subject_hash`
FROM `apple_account_deletions` AS deletion
JOIN `apple_identity_links` AS identity ON identity.`owner_id`=deletion.`owner_id`
WHERE deletion.`delete_owner_data`=1
ON CONFLICT(`deletion_key_hash`,`apple_subject_hash`) DO NOTHING;--> statement-breakpoint
PRAGMA optimize;
