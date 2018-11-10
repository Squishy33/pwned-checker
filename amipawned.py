#!/usr/bin/python3
# Script for checking if your email has been compromised
# and sites.....
# created using the haveibeenpwned API v2
# by Squishy
# 
#	Requirement:
#	Install tabulate library using pip3
#	> sudo apt-get install python-pip3
#	> pip3 install tabulate
#
#	Guide:
#		-h	=	shows help message
#		-e	=	single email or multiple email input. ex ./amipawned -e example1@gmail.com,example1@gmail.com
#		-l	=	single site, multiple site or 'all' input. ex ./amipawned -l site1,site2 or ./amipawned -l all
#		-f	=	input mail or site file lists; file's can be anywhere and mail/site should be in the format as 'sample_email_list' or 'sample_site_list'
#		-o	=	output result; result by default will in the directory where 'amipawned' is located unless if specify
#		-p 	=	password checking
#
#
#
#	Usage:
#	For single or multiple email;
#	./amipawned example_email1@email.com,example_email2@email.com
#
#	For single or multiple email;
#	./amipawned -e example_email1@email.com,example_email2@email.com
#
#	For single or multiple breached site;
#	./amipawned -e site_name1,site_name2
#
#	For single or multiple email output to a file;
#	./amipawned -l example_email1@email.com,example_email2@email.com -o result_output
#
#	For single or multiple breached site output to a file;
#	./amipawned -l site_name1,site_name2 -o result_output
#
#	Using an email list or site list;
#	./amipawned -f file_mails_or_sites
#
#	Using an email list or site list, output result to a file;
#	./amipawned -f file_mails_or_sites -o result_output
#
#	Checkiing password
#	./amipawned -p


import requests
import time
import argparse
import re
import os.path
import getpass
import hashlib
from tabulate import tabulate



#   gets response of the telegram API using the our bot token
def get_url(url):
	resp= requests.get(url)
	if resp.status_code == 404:
		print("\n=====================================================================")
		print("Information cannot be found from the compromised database!")
		return False
	elif resp.status_code == 400:
		print("Bad Request! Try Again!")
		exit(0)
	elif resp.status_code == 403:
		print("FORBIDDEN")
		exit(0)
	elif resp.status_code == 429:
		print("Rate Limiting! check '-h' for delay.")
		exit(0)
	else:
		content = resp.json()
		return content


#   get current msg from the user, return a json format
def emailcheck(email):
	url = "https://haveibeenpwned.com/api/v2/breachedaccount/{}".format(email)
	cont = get_url(url)
	return cont

# chooses is url for the user, if user wants to get all the breached sites or one specific site
def allbreaches(breach_site=None):
	if breach_site == None:
		cont = get_url("https://haveibeenpwned.com/api/v2/breaches")
		return cont
	else:
		url = "https://haveibeenpwned.com/api/v2/breach/{}".format(breach_site)
		cont = get_url(url)
		return cont

# function for checking password if available in haveibeenpawned
def password_check(hash_to_check):
	url = "https://api.pwnedpasswords.com/range/{}".format(hash_to_check)
	return requests.get(url)
	
		
# gets arguements that has been used by the user
def get_arg():
	parser = argparse.ArgumentParser(description='PWNED Checker!!')
	parser.add_argument( 'single_mail', help='Single email query, ex. example@mail.com,example@mail.com', type=str, nargs='?')
	parser.add_argument('-e','--email-lists', help='Single email or multiple email list, ex. example@mail.com,example@mail.com', type=str, dest='email_lists', nargs='?')
	parser.add_argument('-l', '--list-breaches', help='Check if the site has been breached ex. ./amipwned -l site_name, or gets all the list of breaches ex. ./amipwned -l all', type=str, dest='list_all_breaches', nargs="?")
	parser.add_argument('-f', '--file-input', help='File containing email to check', type=str, dest='file_list', nargs='?')
	parser.add_argument('-o', '--output', help='File Output', type=str, dest='output_file', nargs='?')
	parser.add_argument('-p', help='File Output', dest='password', action='store_true')
	return parser.parse_args()

# checks is email is valid (containing symbols)
def email_valid(email):
	reg = "^[_a-z0-9-]+(\.[_a-z0-9-]+)*@[a-z0-9-]+(\.[a-z0-9-]+)*(\.[a-z]{2,4})$"
	if re.match(reg, email):
		return True
	else:
		return False

# get specified breached site
def check_breached_site(breaches_list):
	breaches = breaches_list
	data = []
	dataClass = ""
	for classes in breaches['DataClasses']:
		dataClass += "{}\n".format(classes)
	
	data.append([breaches['Name'], breaches['Domain'], breaches['BreachDate'], breaches['AddedDate'], breaches['PwnCount'], dataClass, breaches['IsVerified']])

	table = tabulate(data, headers=['Name', 'Domain', 'BreachDate', "AddedDate", "PWN Count", "Compromised Data", "Verified"],  tablefmt="grid")
	return table

# get all breached sites for 'all'
def all_breached_sites(breaches_list):
	data = []
	for breach in breaches_list:
		dataClass = ""
		
		for classes in breach['DataClasses']:
			dataClass += "{}\n".format(classes)
	
		data.append([breach['Name'], breach['Domain'], breach['BreachDate'], breach['AddedDate'], breach['PwnCount'], dataClass, breach['IsVerified']])

	table = tabulate(data, headers=['Name', 'Domain', 'BreachDate', "AddedDate", "PWN Count", "Compromised Data", "Verified"],  tablefmt="grid")
	return table

# outputs file using -o, which arguement actually appends the file.
def outputfile(file_name, output_data):
	current_dir = os.getcwd()
	try:
		with open(os.path.join(current_dir, file_name), "a") as output_file:
			output_file.write(output_data + "\n")
			print("Data Saved!")
	except Exception as e:
		print("Path Doesnt Exist!")

# gets file specified by the user having an email list or a site breach list
def open_file(file_path, output_file=False):
	if os.path.exists(file_path):
		if os.path.isfile(file_path):
			mails = []
			sites = []
			ismail = input("What is this file list (mails or sites)? ")
			print("=====================================================================\n")
			if ismail == "mails":
				with open(file_path, "r") as input_file:
					for line in input_file:
						if email_valid(line.rstrip()):
							mails.append(line.rstrip())
						else:
							print("Invalid Email: {}".format(line))
				mails_breached_iter(mails, output_file)

			elif ismail == "sites":
				with open(file_path, "r") as input_file:
					breaches_list = []
					for line in input_file:
						breaches_list.append(line.rstrip())
				for single_breach in breaches_list:
					breached_site = allbreaches(single_breach)
					if breached_site:
						data_output = check_breached_site(breached_site)
						if output_file:
							outputfile(output_file, data_output)
						else:
							print(check_breached_site(breached_site))
					else:
						print("Site: {}".format(single_breach))
						print("=====================================================================\n")
			else:
				print("File list should either be an email list or a site list.")
				exit(0) 
		else:
			print("No File Detected!")

	else:
		print("File Doesnt Exist! {}".format(file_path))

# this function iterate through the email list that has been provided
def mails_breached_iter(mails, output_file=False):
	for mail in mails:
		content = emailcheck(mail)
		if content:
			data = []
			for breach in content:
				dataClass = ""
				
				for classes in breach['DataClasses']:
					dataClass += "{}\n".format(classes)
			
				data.append([breach['Name'], breach['Domain'], breach['BreachDate'], breach['AddedDate'], dataClass, breach['IsVerified']])

			table = tabulate(data, headers=['Name', 'Domain', 'BreachDate', "AddedDate", "Compromised Data", "Verified"],  tablefmt="grid")
			if output_file:
				data_print = "\nEmail: {}\n".format(mail)
				data_print += table
				outputfile(output_file, data_print)
			else:                    
				print("\nEmail: {}\n".format(mail))
				print(table)
		else:
			print("Email: {}".format(mail))
			print("=====================================================================\n")

def hashes_output_iter(hashes_output, prefix, postfix):
	find = True
	#postfix = sha1_digest[5:len(sha1_digest)]
	for hashes in hashes_output.text.split('\n'):
		hash_post, count = hashes.split(':')
		count = int(count)
		if postfix == hash_post:
			print("=====================================================================")
			print("Password Hash: {}".format(prefix+postfix))
			print("Number of times this password was used: {}".format(count))
			print("=====================================================================\n")
			find = True
			break
		else:
			find = False
	if find == False:
		# if nothing can be found within the hash dumps
		print("=====================================================================")
		#print("Password Hash: {}".format(sha1_digest))
		print("Your password was not found in the library of 1B+ passwords.")
		print("=====================================================================\n")

def main():
	banner = """
   _              _____  ___                              _ 
  /_\  _ __ ___   \_   \/ _ \__ ___      ___ __   ___  __| |
 //_\\| '_ ` _ \   / /\/ /_)/ _` \ \ /\ / / '_ \ / _ \/ _` |
/  _  \ | | | | /\/ /_/ ___/ (_| |\ V  V /| | | |  __/ (_| |
\_/ \_/_| |_| |_\____/\/    \__,_| \_/\_/ |_| |_|\___|\__,_|
                                                            
	"""
	args = get_arg()
	print(banner)
	print("Please wait, this wont take long.....")
	print("=====================================================================")
	time.sleep(2)
	if args.email_lists or args.single_mail:
		email = args.email_lists or args.single_mail
		mails = []
		for mail in email.split(','):
			if email_valid(mail):
				mails.append(mail)
			else:
				print("Invalid Email: {}".format(mail))
		mails_breached_iter(mails, args.output_file)
		
	elif args.list_all_breaches:
		if args.list_all_breaches == 'all':
			breaches_list = allbreaches()
			data_output = all_breached_sites(breaches_list)
			if args.output_file:
				outputfile(args.output_file, data_output)
			else:
				print(all_breached_sites(breaches_list))
			
		else:
			input_breaches = args.list_all_breaches
			list_breaches = []
			for breach in input_breaches.split(','):
				list_breaches.append(breach)
			for single_breach in list_breaches:
				breaches_list = allbreaches(single_breach)
				if breaches_list:
					data_output = check_breached_site(breaches_list)
					if args.output_file:
						outputfile(args.output_file, data_output)
					else:
						print(check_breached_site(breaches_list))
				else:
					print("Site: {}".format(single_breach))
					print("=====================================================================\n")
	
	elif args.file_list:
		open_file(args.file_list, args.output_file)

	elif args.password:
		pswd = getpass.getpass("Enter Password to check: ")
		# 6367c48dd193d56ea7b0baad25b19455e529f5ee abc123
		hash_output = hashlib.sha1(pswd.encode('utf-8'))
		sha1_digest = hash_output.hexdigest().upper()
		prefix = sha1_digest[:5]
		postfix = sha1_digest[5:len(sha1_digest)]
		hashes_output_iter(password_check(prefix),prefix,postfix)


		

	else:
		print("Syntax Error!!")



if __name__ == '__main__':
	main()
