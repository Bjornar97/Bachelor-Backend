CREATE DATABASE IF NOT EXISTS user;

USE user;

CREATE TABLE IF NOT EXISTS user_table (
  user_id int(16) NOT NULL,
  user_email varchar(128) NOT NULL,
  user_name varchar(128) DEFAULT NULL,
  user_password varchar(93) DEFAULT NULL,
  user_phone int(11) DEFAULT NULL,
  user_city varchar(128) DEFAULT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY Uemail_UNIQUE (user_email),
  UNIQUE KEY Uname_UNIQUE (user_name)
);

CREATE TABLE IF NOT EXISTS token_whitelist (
  id int(11) NOT NULL AUTO_INCREMENT,
  jti varchar(128) DEFAULT NULL,
  PRIMARY KEY (id)
);

