#!/usr/bin/env python3

from flask import Flask, request, jsonify
import requests
import sys
import json
import mariadb
import bcrypt

app = Flask(__name__)
config_file = "config.json"

# Load the config
try:
	with open(config_file, "r") as f:
		config = json.load(f)
except FileNotFoundError:
	print("The file " + config_file + " does not exist.")
	exit()
except json.decoder.JSONDecodeError:
	print("Cannot decode config.json.")
	exit()
except Exception as e:
	# Print the error if an error occured
	print("Oops!", e.__class__, "occurred.")
	exit()

# Connect to MariaDB Platform
try:
	db = mariadb.connect(
		user=config["database"]["user"],
		password=config["database"]["password"],
		host=config["database"]["host"],
		port=config["database"]["port"],
		database=config["database"]["database_name"]
	)
except mariadb.Error as e:
	print(f"Error connecting to MariaDB Platform: {e}")
	sys.exit(1)


@app.route("/")
def hello_world():
	# Return the IP of client (usefull for debugging)
	if request.environ.get('HTTP_X_FORWARDED_FOR') is None:
		ip = request.environ['REMOTE_ADDR']
	else:
		ip = request.environ['HTTP_X_FORWARDED_FOR'] # If the user is behind a proxy (i.e. nginx)
	print("Client IP:",ip)
	return "This should work <p hidden>" + str(ip) + "</p>"

@app.route("/scr/get_global_score.php", methods=['POST', 'GET'])
def get_global_score():
	username = request.args.get('n')

	# Check for empty username (illegal) and make sure it only contains alpha numeric characters
	if (username == '' or username is None) or not username.isalnum():
		print ("Illegal username, no good")
		return "false"

	cursor = db.cursor()
	cursor.execute("SELECT score FROM user_scores WHERE user_name = %s", (username,))
	result = cursor.fetchone()
	
	if result is not None:
		# User found in the local database, return the local score
		score = result[0]
	else:
		# User not found locally, fetch the score from the 17Studio's server
		external_server_response = requests.get("http://drserver17.com/scr/get_global_score.php", params={'n': username})
		if external_server_response.ok:
			try:
				external_server_score = int(external_server_response.text)
			except Exception as e:
				print(f"Error retriving score from drserver17.com: {e}")
				return ""
				
			if external_server_score > 0:
				# Save the score in the local database
				cursor.execute("INSERT INTO user_scores (user_name, score) VALUES (%s, %s)", (username, external_server_score))
				db.commit()
				score = external_server_score
			else:
				return ""
		else:
			# If the request to 17Studio's server fail
			return "drserver17.com is kaput x_x"
		
	cursor.close()

	return str(score)

@app.route("/scr/find_nick_pass.php", methods=['POST', 'GET'])
def find_nick_pass():
	username = request.args.get('n')
	password = request.args.get('p')
	
	# Check for empty username or password (illegal) and make sure they only contains alpha numeric characters
	if (username == '' or password == '' or username is None or password is None) or (not username.isalnum() and not password.isalnum()):
		print ("Username or password empty, sus")
		return "false"

	# Retrieve the stored salt and hashed password from the database
	cursor = db.cursor()
	try:
		cursor.execute("SELECT password_hash, salt FROM user_credentials WHERE user_name = ?", (username,))
	except mariadb.ProgrammingError:
		# If for some reason I fogor to create the tabs for the user credentials
		print("Creating TABLE user_credentials...")
		cursor.execute("CREATE TABLE user_credentials (user_name VARCHAR(255) NOT NULL, password_hash CHAR(60) NOT NULL, salt BINARY(32) NOT NULL)")
		cursor.execute("SELECT password_hash, salt FROM user_credentials WHERE user_name = ?", (username,))

	result = cursor.fetchone()

	if result is not None:
		print("Using username and pass from my DB :)")
		stored_password_hash = result[0]
		salt = result[1]
		
		# Compare the stored hashed password with the hashed provided password
		if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash.encode()):
			return "true"
		else:
			return "false"
		
	else:
		print("Using username and pass from 17Studio's DB")

		external_server_response = requests.get("http://drserver17.com/scr/find_nick_pass.php", params={'n': username, 'p': password})
		print(external_server_response.text)
		if external_server_response.ok:
		
			# Check if the password is valid according to 17Studio's server
			if(external_server_response.text == 'true'):
				print("Valid password according to 17")
				
				salt = bcrypt.gensalt()
				password_hash = bcrypt.hashpw(password.encode('utf-8'), salt)

				# Insert the username, password hash and salt into the table
				cursor.execute("INSERT INTO user_credentials (user_name, password_hash, salt) VALUES (?, ?, ?)", (username, password_hash, salt))
				db.commit()
			
			# Return 17Studio's answer
			return external_server_response.text
		else:
			# If the request to 17Studio's server fail
			return "drserver17.com/scr/find_nick_pass.php is kaput x_x"

@app.route("/scr/get_died.php", methods=['POST', 'GET'])
def get_died():
	# Retrieve number of death from the database
	cursor = db.cursor()
	try:
		cursor.execute("SELECT count FROM death_count")
	except mariadb.ProgrammingError:
		# If for some reason I fogor to create the table for the death count
		print("Creating TABLE death_count...")
		cursor.execute("CREATE TABLE death_count (count BIGINT DEFAULT 0 NOT NULL)")
		cursor.execute("INSERT INTO death_count (`count`) VALUES(0)")

	result = cursor.fetchone()

	return str(result[0])

@app.route("/scr/add_died.php", methods=['POST', 'GET'])
def add_died():
	# Add one to the number of death
	cursor = db.cursor()
	try:
		cursor.execute("UPDATE death_count SET count = count + 1")
		db.commit
	except mariadb.ProgrammingError:
		# If for some reason I fogor to create the table for the death count
		print("Creating TABLE death_count...")
		cursor.execute("CREATE TABLE death_count (count BIGINT DEFAULT 0 NOT NULL)")
		cursor.execute("INSERT INTO death_count (`count`) VALUES(0)")
	cursor.execute("SELECT count FROM death_count")

	result = cursor.fetchone()

	return str(result[0])

@app.route("/get_sale.php", methods=['POST', 'GET'])
def get_sale():
	return '[["1","0","0"],["2","0","0"],["3","50","4.99"],["4","50","2.99"],["5","50","0.99"],["6","0","0"],["7","0","0"],["8","0","0"],["9","0","0"],["10","0","0"],["11","0","0"],["12","0","0"],["13","0","0"],["14","50","49.99"],["15","0","0"]]'

@app.route("/scr/get_ver.php", methods=['POST', 'GET'])
def get_ver():
	return '[1697403948,"24"]'

if __name__ == "__main__":
	app.run(debug=True)
