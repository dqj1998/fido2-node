-- Migration script to add transports column to existing attestations table
-- Run this if you already have an existing database

USE fido2_node_db;

ALTER TABLE attestations ADD COLUMN `transports` varchar(100) AFTER `user_agent`;
