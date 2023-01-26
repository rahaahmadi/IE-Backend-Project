import mysql.connector

mydb = mysql.connector.connect(
  host="127.0.0.1",
  user="root",
  database="web_db"
)

  
try:
  cursor = mydb.cursor()
  cursor.execute("CREATE TABLE IF NOT EXISTS User (id int PRIMARY KEY AUTO_INCREMENT, username varchar(255) NOT NULL, password varchar(255) NOT NULL, created_at datetime);")
  cursor.execute("CREATE TABLE IF NOT EXISTS Url (id int PRIMARY KEY AUTO_INCREMENT, address varchar(255) NOT NULL, user_id int NOT NULL, created_at datetime, threshold int NOT NULL, failed_times int DEFAULT 0, FOREIGN KEY (user_id) REFERENCES User(id));")
  cursor.execute("CREATE TABLE IF NOT EXISTS Request (id int PRIMARY KEY AUTO_INCREMENT, created_at datetime, result int);")
  mydb.commit()
finally:
  mydb.close()