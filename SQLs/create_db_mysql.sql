
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
    `username` varchar(320) NOT NULL, -- can save email addresses
    `displayname` varchar(320) NOT NULL,
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
    `fmt` varchar(32) NOT NULL,
    `aaguid` varchar(36) NOT NULL,
    `credid_base64` text NOT NULL,
    `unique_device_id` char(36),
    `user_agent` varchar(256),
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `deleted` DATETIME DEFAULT NULL,
    PRIMARY KEY (`attest_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8mb4 COMMENT='user attestations';

alter table attestations add index attestations_IDX1(user_id);
alter table attestations add index attestations_IDX2(created);
alter table attestations add index attestations_IDX3(deleted);

CREATE TABLE IF NOT EXISTS `user_sessions` (
    `session_id` char(40) NOT NULL,
    `user_id` char(40) NOT NULL,
    `actived` DATETIME DEFAULT CURRENT_TIMESTAMP,
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`session_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=ascii COMMENT='user sessions';

alter table user_sessions add index user_sessions_IDX1(actived);
alter table user_sessions add index user_sessions_IDX2(created);

CREATE TABLE IF NOT EXISTS `user_actions` (
    `action_id` char(40) NOT NULL,
    `user_id` char(40) NOT NULL,
    `action_type` tinyint unsigned NOT NULL default 1, -- 0: register, 1: authenticate
    `action_session` char(50) NOT NULL,  
    `error` varchar(16) default '', -- ''=succ; error code
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`action_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=ascii COMMENT='user actions';

alter table user_actions add index user_actions_IDX1(action_type);
alter table user_actions add index user_actions_IDX2(error);
alter table user_actions add index user_actions_IDX3(action_session);
alter table user_actions add index user_actions_IDX4(user_id);
alter table user_actions add index user_actions_IDX5(created);

CREATE TABLE IF NOT EXISTS `registration_sessions` (
    `session_id` char(40) NOT NULL,
    `username` varchar(320) NOT NULL, -- can save email addresses
    `displayname` varchar(320) NULL,
    `created` DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`session_id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8mb4 COMMENT='registration sessions';
alter table registration_sessions add index registration_sessions_IDX1(created);