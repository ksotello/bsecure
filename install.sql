
CREATE DATABASE IF NOT EXISTS `bsecure`;

USE `bsecure`;

CREATE TABLE `bsecure`.`bst_users`
(
  `uid` INT NOT NULL,
  `username` VARCHAR(30) NOT NULL,
  `password` VARCHAR(64) NOT NULL,
    
  CONSTRAINT `BS_USERS_PK` PRIMARY KEY(`uid`),
  CONSTRAINT `BS_USERS_UN` UNIQUE(`username`)
);

CREATE TABLE `bsecure`.`bst_online`
(
  `uid` INT NOT NULL,
  `ip` VARCHAR(15) NOT NULL,
  `fingerprint` VARCHAR(64) NOT NULL,
  
  CONSTRAINT `BS_ONLINE_PK` PRIMARY KEY(`uid`),
  CONSTRAINT `BS_ONLINE_FK` FOREIGN KEY(`uid`) REFERENCES `bst_users`(`uid`) ON DELETE CASCADE
);

-- Test to ensure failure
CREATE USER 'bsu_newuser'@'localhost' IDENTIFIED BY ;
GRANT INSERT ON `bsecure`.`bst_users` TO 'bsu_newuser'@'localhost';

CREATE USER 'bsu_auth'@'localhost' IDENTIFIED BY ;
GRANT SELECT ON `bsecure`.`bst_users` TO 'bsu_auth'@'localhost';
GRANT SELECT,INSERT,UPDATE,DELETE ON `bsecure`.`bst_online` TO 'bsu_auth'@'localhost';