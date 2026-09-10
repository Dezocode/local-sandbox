import { integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';
export const workspaces=sqliteTable('workspaces',{userId:text('user_id').primaryKey(),policy:text('policy').notNull(),completed:text('completed').notNull(),revision:integer('revision').notNull().default(0)});
export const files=sqliteTable('files',{userId:text('user_id').notNull(),path:text('path').notNull(),content:text('content').notNull(),version:integer('version').notNull().default(0)},t=>[primaryKey({columns:[t.userId,t.path]})]);
export const receipts=sqliteTable('receipts',{userId:text('user_id').notNull(),id:text('id').notNull(),payload:text('payload').notNull(),createdAt:text('created_at').notNull()},t=>[primaryKey({columns:[t.userId,t.id]})]);
export const usage=sqliteTable('usage',{userId:text('user_id').notNull(),window:text('window').notNull(),calls:integer('calls').notNull().default(0)},t=>[primaryKey({columns:[t.userId,t.window]})]);
