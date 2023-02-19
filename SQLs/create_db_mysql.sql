
CREATE DATABASE fido2_node_db default character set utf8mb4;
use fido2_node_db;

CREATE TABLE IF NOT EXISTS `registered_rps` (
    `rp_id` int(12) unsigned NOT NULL AUTO_INCREMENT,
    `rp_domain` varchar(255) NOT NULL COMMENT 'rp domain',
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `deleted` DATETIME DEFAULT NULL,
    PRIMARY KEY (`rp_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COMMENT='registered rps';

alter table registered_rps add index registered_rps_IDX1(rp_domain);
alter table registered_rps add index registered_rps_IDX2(created);
alter table registered_rps add index registered_rps_IDX3(deleted);

CREATE TABLE IF NOT EXISTS `registered_users` (
    `user_id` char(40) NOT NULL,
    `rp_id` int(12) unsigned NOT NULL,
    `username` varchar(255) NOT NULL,    
    `displayname` varchar(255) NOT NULL,
    `registered` boolean default false,
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `deleted` DATETIME DEFAULT NULL,
    PRIMARY KEY (`user_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COMMENT='registered users';

alter table registered_users add index registered_users_IDX1(rp_id, username);
alter table registered_users add index registered_users_IDX2(created);
alter table registered_users add index registered_users_IDX3(deleted);

CREATE TABLE IF NOT EXISTS `attestations` (
    `attest_id` int(12) unsigned NOT NULL AUTO_INCREMENT,
    `user_id` char(40) NOT NULL,
    `public_key` text NOT NULL,
    `counter` int default 0,
    `fmt` varchar(16) NOT NULL,
    `aaguid` varchar(36) NOT NULL,    
    `credid_base64` text NOT NULL,
    `unique_device_id` char(36),
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `deleted` DATETIME DEFAULT NULL,
    PRIMARY KEY (`attest_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COMMENT='user attestations';

alter table attestations add index attestations_IDX1(user_id);
alter table attestations add index attestations_IDX2(created);
alter table attestations add index attestations_IDX3(deleted);

