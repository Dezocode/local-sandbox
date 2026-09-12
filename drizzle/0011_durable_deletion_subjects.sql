CREATE TABLE `apple_account_deletion_subjects` (
	`deletion_key_hash` text NOT NULL,
	`apple_subject_hash` text NOT NULL,
	PRIMARY KEY(`deletion_key_hash`, `apple_subject_hash`),
	FOREIGN KEY (`deletion_key_hash`) REFERENCES `apple_account_deletions`(`deletion_key_hash`) ON UPDATE no action ON DELETE cascade
);--> statement-breakpoint
INSERT INTO `apple_account_deletion_subjects` (`deletion_key_hash`,`apple_subject_hash`)
SELECT `deletion_key_hash`,`apple_subject_hash`
FROM `apple_account_deletions`
WHERE `delete_owner_data`=0
ON CONFLICT(`deletion_key_hash`,`apple_subject_hash`) DO NOTHING;--> statement-breakpoint
PRAGMA optimize;
