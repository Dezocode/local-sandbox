ALTER TABLE `sync_workspaces` ADD `revision` integer DEFAULT 0 NOT NULL;
--> statement-breakpoint
CREATE TRIGGER `sync_records_workspace_revision_after_insert`
AFTER INSERT ON `sync_records`
BEGIN
	UPDATE `sync_workspaces`
	SET `revision` = `revision` + 1, `updated_at` = NEW.`updated_at`
	WHERE `user_id` = NEW.`user_id` AND `workspace_id` = NEW.`workspace_id`;
END;
--> statement-breakpoint
CREATE TRIGGER `sync_records_workspace_revision_after_update`
AFTER UPDATE OF `revision`, `mutation_id`, `envelope` ON `sync_records`
BEGIN
	UPDATE `sync_workspaces`
	SET `revision` = `revision` + 1, `updated_at` = NEW.`updated_at`
	WHERE `user_id` = NEW.`user_id` AND `workspace_id` = NEW.`workspace_id`;
END;
