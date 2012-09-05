DROP TABLE IF EXISTS users;
CREATE TABLE users (
	user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	user_name STRING NOT NULL, 
	user_pw_hash STRING NOT NULL,
	user_role INTEGER NOT NULL, 
	user_status INTEGER NOT NULL, 
	user_gender BOOLEAN NOT NULL, 
	user_zipcode INTEGER, 
	user_age INTEGER, 
	user_join_date TIMESTAMP NOT NULL, 
	last_modified TIMESTAMP NOT NULL
);

DROP TABLE IF EXISTS categories;
CREATE TABLE categories (
	category_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	category_name STRING NOT NULL, 
	pub_date TIMESTAMP NOT NULL, 
	last_modified TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL, 
	FOREIGN KEY(user_id) REFERENCES users(user_id)	
);

DROP TABLE IF EXISTS questions;
CREATE TABLE questions (
	question_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	question_text STRING NOT NULL,
	category_id INTEGER NOT NULL, 
	pub_date TIMESTAMP NOT NULL,
	last_modified TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL,
    FOREIGN KEY(category_id) REFERENCES categories(category_id),	
	FOREIGN KEY(user_id) REFERENCES users(user_id)	
);

DROP TABLE IF EXISTS answers;
CREATE TABLE answers (
	answer_id INTEGER PRIMARY KEY AUTOINCREMENT, 
	answer_choice BOOLEAN NOT NULL,
	question_id INTEGER NOT NULL,
	pub_date TIMESTAMP NOT NULL, 
	last_modified TIMESTAMP NOT NULL,
    user_id INTEGER NOT NULL, 
    FOREIGN KEY(question_id) REFERENCES questions(question_id),
	FOREIGN KEY(user_id) REFERENCES users(user_id)	
);
