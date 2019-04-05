CREATE DATABASE IF NOT EXISTS user;

USE user;

CREATE TABLE IF NOT EXISTS user_table (
  user_id int(16) NOT NULL,
  user_email varchar(128) NOT NULL,
  user_name varchar(128) NOT NULL,
  user_password varchar(93) DEFAULT NULL,
  user_phone int(11) DEFAULT NULL,
  PRIMARY KEY (user_id),
  UNIQUE KEY Uemail_UNIQUE (user_email),
  UNIQUE KEY Uname_UNIQUE (user_name)
);

CREATE TABLE IF NOT EXISTS trips_table (
  user_id int(16) NOT NULL,
  trip_id int(16) NOT NULL AUTO_INCREMENT,
  trip_json text NOT NULL,
  is_public boolean,
  PRIMARY KEY (trip_id),
  FOREIGN KEY (user_id) references user_table(user_id)
  on update cascade on delete restrict
);

CREATE TABLE IF NOT EXISTS friends_table (
  user_id int(16) NOT NULL,
  friend_id int(16) NOT NULL,
  friend_status varchar(20) NOT NULL,
  PRIMARY KEY (user_id, friend_id),
  FOREIGN KEY (user_id) references user_table(user_id)
  on update cascade on delete restrict,
  FOREIGN KEY (friend_id) references user_table(user_id)
  on update cascade on delete restrict
);

CREATE TABLE IF NOT EXISTS token_whitelist (
  id int(11) NOT NULL AUTO_INCREMENT,
  jti varchar(128) DEFAULT NULL,
  PRIMARY KEY (id)
);