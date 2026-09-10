CREATE TABLE `files` (
	`user_id` text NOT NULL,
	`path` text NOT NULL,
	`content` text NOT NULL,
	`version` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`user_id`, `path`)
);
--> statement-breakpoint
CREATE TABLE `receipts` (
	`user_id` text NOT NULL,
	`id` text NOT NULL,
	`payload` text NOT NULL,
	`created_at` text NOT NULL,
	PRIMARY KEY(`user_id`, `id`)
);
--> statement-breakpoint
CREATE TABLE `usage` (
	`user_id` text NOT NULL,
	`window` text NOT NULL,
	`calls` integer DEFAULT 0 NOT NULL,
	PRIMARY KEY(`user_id`, `window`)
);
--> statement-breakpoint
CREATE TABLE `workspaces` (
	`user_id` text PRIMARY KEY NOT NULL,
	`policy` text NOT NULL,
	`completed` text NOT NULL,
	`revision` integer DEFAULT 0 NOT NULL
);
