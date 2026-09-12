CREATE INDEX `apple_account_deletions_expiry_idx` ON `apple_account_deletions` (`expires_at`,`deletion_key_hash`);--> statement-breakpoint
CREATE INDEX `apple_auth_notifications_expiry_idx` ON `apple_auth_notifications` (`expires_at`,`notification_id_hash`);--> statement-breakpoint
PRAGMA optimize;
