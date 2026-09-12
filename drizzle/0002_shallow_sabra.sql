CREATE TABLE `sync_records` (
	`user_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`record_id` text NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL,
	`mutation_id` text NOT NULL,
	`envelope` text NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY(`user_id`, `workspace_id`, `record_id`)
);
--> statement-breakpoint
CREATE TABLE `sync_workspaces` (
	`user_id` text NOT NULL,
	`workspace_id` text NOT NULL,
	`epoch` text NOT NULL,
	`recovery` text NOT NULL,
	`created_at` text NOT NULL,
	`updated_at` text NOT NULL,
	PRIMARY KEY(`user_id`, `workspace_id`)
);
