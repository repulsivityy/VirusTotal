__date__ = "August, 2023"
__version__ = "1.22"
__x_app_name__ = 'MAVE-lite.v' + __version__
__note__ = "You may not use this script except in compliance with the LICENSE.txt file provided with this script."

import sys
import re
import os
import time
import logging
import requests
import argparse
import threading
import itertools
import traceback
from requests.auth import HTTPBasicAuth
from keys import APIv4_PUBLIC, APIv4_SECRET
from proxy_config import ENABLE_PROXY, HOST, PORT, PROXY_USR, PROXY_PASS, NEED_PASS
from jinja2 import Environment, FileSystemLoader
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import wait
import signal

payload = {}
headers = {
	'Content-Type': "application/json",
	'Accept': "application/json",
	'X-App-Name': __x_app_name__
	}
unknown = []
unknown_len = 0
failed = []
output = []
threads = []

MAX_THREAD_CONST = 50
max_threads = 50
proxies = None
COMMA = ","
exit_event = threading.Event()
session = None

def show_progress():
	progress_chars = ['|', '/', '-', '\\']
	part_completed = len(output) + len(failed) + unknown_len
	total = input_length
	for c in itertools.cycle(progress_chars):
		percents = round(100.0 * part_completed / float(total), 1)
		sys.stdout.write(f'\rProcessing... {percents}% completed... {len(failed)} failed, {unknown_len} unknown and {len(output)} successful...' + c)
		if part_completed >= total or exit_event.is_set():
			break
		sys.stdout.flush()
		time.sleep(0.5)
		part_completed = len(output) + len(failed) + unknown_len

def signal_handler(signum, frame):
	print(f'Inside signal_handler: {signum}')
	output_filename = "output" + os.path.sep + vulnfilename + "_partial"
	sys.stdout.write('\r')
	sys.stdout.flush()
	with open(output_filename + '.html', 'w', encoding='utf-8') as static_content:
		static_content.write(template.render(cve_data=output))
	if need_csv:
		write_csv(output_filename)
	logging.info(f"Output file {output_filename + '.html'} written!")
	exit_event.set()
	sys.exit(0)

def check_dirs():
	folders = ["logs", "output"]
	for folder in folders:
		if not os.path.exists(folder):
			os.makedirs(folder)

def regex_file():
	try:
		cveRaw = None
		with open(vulnfile, 'r', encoding='utf-8') as vuln:
			cveRaw = vuln.read()
		cves = []
		vulns = re.findall(r'(?i)CVE-\d{4}-\d{4,7}', cveRaw)
		for cve in vulns:
			#cves.append('"'+cve+'"')
			cves.append(cve.upper())
		cves = list(set(cves))
		cves.sort()
	except Exception as e:
		raise Exception(f"Could not read the file, make sure a valid existing file name is provided, {e}")
	return cves

def replace_chars(data):
	replaced_data = data.replace('<', '&lt;')
	replaced_data = replaced_data.replace('>', '&gt;')
	return replaced_data

def check_proxy():
	global proxies
	if 'y' == ENABLE_PROXY.lower():
		if 'y' != NEED_PASS.lower():
			proxies = {
				'http': 'http://' + HOST + ':' + str(PORT),
				'https': 'https://' + HOST + ':' + str(PORT)
			}
		else:
			proxies = {
				'http': 'http://' + PROXY_USR + ':' + PROXY_PASS + '@' + HOST + ':' + str(PORT),
				'https': 'https://' + PROXY_USR + ':' + PROXY_PASS + '@' + HOST + ':' + str(PORT)
			}

def trim_date_part(input_date):
	if input_date is not None:
		return input_date[0:input_date.index('T')]
	else:
		return ""

def divide_chunks(input, size):
	for x in range(0, len(input), size):
		yield input[x:x+size]

def diff_list(cves_p, cves_resp):
	return list(filter(lambda x: x not in cves_resp, cves_p))

def post_vuln_lookup(cves_p):
	global unknown_len
	output_arr = []
	cves_with_resp = []
	try:
		payload = {
			"rating_types": [
				"unrated",
				"analyst",
				"predicted"
			],
			"requests": [{"values": cves_p}],
			"limit": 100
		}
		url = "https://api.intelligence.mandiant.com/v4/vulnerability"
		# sending post request and saving response as response object
		resp = requests.post(url, headers=headers, json=payload, proxies=proxies)
		logging.info(f'API Response: {resp.status_code} for {cves_p}')
		with session.post(url, headers=headers, json=payload, proxies=proxies) as resp:
			if resp.status_code == 200:
				response = resp.json()['vulnerabilities']
				for vuln_object in response:
					#response = response.json()
					cve = ''
					vuln_id = ''
					title = ''
					risk_rating = ''
					exploit_rating = ''
					published_date = ''
					date_of_disclosure = ''
					was_zero_day = False
					v2_base = ''
					v2_temporal = ''
					v3_base = ''
					v3_temporal = ''
					user_interaction = ''
					associated_actors = []
					associated_malware = []
					exploitation_vectors = []
					if 'cve_id' in vuln_object:
						cve = vuln_object['cve_id']
						cves_with_resp.append(cve)
					if 'id' in vuln_object:
						vuln_id = vuln_object['id']
					if 'title' in vuln_object:
						title = replace_chars(null_to_dash(vuln_object['title']))
					if 'risk_rating' in vuln_object:
						risk_rating = null_to_dash(vuln_object['risk_rating'])
					if 'exploitation_state' in vuln_object:
						exploit_rating = null_to_dash(vuln_object['exploitation_state'])
					if 'exploitation_vectors' in vuln_object and vuln_object['exploitation_vectors']:
						for exploit_vector in vuln_object['exploitation_vectors']:
							exploitation_vectors.append(exploit_vector)
					if 'publish_date' in vuln_object:
						published_date = vuln_object['publish_date']
						published_date = published_date[0:published_date.index('T')]
					if 'date_of_disclosure' in vuln_object:
						date_of_disclosure = vuln_object['date_of_disclosure']
						date_of_disclosure = trim_date_part(date_of_disclosure)
					if 'was_zero_day' in vuln_object:
						was_zero_day = vuln_object['was_zero_day']
					if 'common_vulnerability_scores' in vuln_object:
						vulnScores = vuln_object["common_vulnerability_scores"]
						for vulnVersion in vulnScores:
							if vulnVersion.startswith("v2."):
								if 'base_score' in vulnScores[vulnVersion]:
									v2_base = vulnScores[vulnVersion]['base_score']
								if 'temporal_score' in vulnScores[vulnVersion]:
									v2_temporal = vulnScores[vulnVersion]['temporal_score']
							elif vulnVersion.startswith("v3."):
								if 'base_score' in vulnScores[vulnVersion]:
									v3_base = vulnScores[vulnVersion]['base_score']
								if 'temporal_score' in vulnScores[vulnVersion]:
									v3_temporal = vulnScores[vulnVersion]['temporal_score']
								if 'user_interaction' in vulnScores[vulnVersion]:
									user_interaction = vulnScores[vulnVersion]['user_interaction']
					if 'associated_actors' in vuln_object and len(vuln_object['associated_actors']) > 0:
						for actor in vuln_object['associated_actors']:
							if 'name' in actor:
								if 'id' in actor:
									associated_actors.append({"Name": actor['name'], "Weblink": "https://advantage.mandiant.com/actors/" + actor["id"]})
								else:
									associated_actors.append({"Name": actor['name'], "Weblink": ""})
					if 'associated_malware' in vuln_object and len(vuln_object['associated_malware']) > 0:
						for malware in vuln_object['associated_malware']:
							if 'name' in malware:
								if 'id' in malware:
									associated_malware.append({"Name": malware['name'], "Weblink": "https://advantage.mandiant.com/malware/" + malware["id"]})
								else:
									associated_malware.append({"Name": malware['name'], "Weblink": ""})

					output_arr.append(
						{"CveId": cve + ":" + vuln_id, "ExploitRating": exploit_rating, "RiskRating": risk_rating,
						 "UserInteraction": user_interaction, "AssociatedActors": associated_actors,
						 "AssociatedMalware": associated_malware, "Title": title,
						 "ExploitationVector": exploitation_vectors, "PublishedDate": published_date,
						 "DateOfDisclosure": date_of_disclosure, "WasZeroDay": was_zero_day,
						 "V3_BaseScore": v3_base, "V3_TemporalScore": v3_temporal, "V2_BaseScore": v2_base,
						 "V2_TemporalScore": v2_temporal})
				output.extend(output_arr)
				if len(cves_p) > len(output_arr):
					unknown_len = unknown_len + (len(cves_p)-len(output_arr))
					unknown.extend(diff_list(cves_p, cves_with_resp))
				logging.info(f'Total length of output: {len(output)}, len(cves_p): {len(cves_p)}, len(output_arr): {len(output_arr)}')
			else:
				logging.info(f'resp.status_code: {resp.status_code} with input length: {len(cves_p)}')
				unknown_len = unknown_len + len(cves_p)
				unknown.extend(cves_p)
	except Exception as e:
		logging.exception(f'An exception occurred in post_vuln_lookup for cves: {cves_p}', exc_info=True)
		failed.extend(cves_p)

def null_to_dash(data):
	replaced_data = "-"
	if data:
		replaced_data = data
	return replaced_data

def get_token():
	token = ''
	request_url = 'https://api.intelligence.mandiant.com/token'
	token_headers = {
		'Content-Type': "application/x-www-form-urlencoded",
		'Accept': "application/json",
		'X-App-Name': __x_app_name__
	}
	token_payload = {"grant_type": "client_credentials"}
	try:
		resp = requests.post(request_url, data=token_payload, headers=token_headers, auth=HTTPBasicAuth(APIv4_PUBLIC, APIv4_SECRET), proxies=proxies)
		if resp.status_code == 200:
			logging.info(f"Token generated successfully")
			token = resp.json()["access_token"]
		else:
			logging.error(f"Could not generate token, status_code: {resp.status_code}. Inputs used were, headers: {token_headers}, payload: {token_payload}")
			#sys.exit(1)
	except Exception as e:
		logging.exception(f"An exception occurred in token generation. {e}")
	return token

def main_post():
	print(f'\nNOTE: {__note__}\n')
	check_dirs()
	load_template()
	parse_args()
	setup_logs()

	try:
		check_proxy()
		cves = regex_file()
		logging.info(f'Executing file: {vulnfile} which has a total of {len(cves)} cves.')
		global input_length
		global headers
		global session
		input_length = len(cves)

		if len(cves) > 50000:
			logging.warning("Too many CVE-IDs to process. Please provide an input file with 50,000 or less CVE-IDs.")
			print("Too many CVE-IDs to process. Please provide an input file with 50,000 or less CVE-IDs.")
			sys.exit(1)
		elif 0 < len(cves) < 50001:
			progress_thread = threading.Thread(target=show_progress)
			progress_thread.start()
			threads.append(progress_thread)

			token = get_token()
			if '' == token:
				print("\nCould not generate token, exiting the system.")
				exit_event.set()
				sys.exit(1)
			session = requests.Session()
			headers = {
				'Content-Type': "application/json",
				'Accept': "application/json",
				'Authorization': f"Bearer {token}",
				'X-App-Name': __x_app_name__
			}

			with ThreadPoolExecutor(max_threads) as executor:
				# submit tasks and collect futures
				try:
					cves_details = [executor.submit(post_vuln_lookup, chunk) for chunk in divide_chunks(cves, 100)]
					# wait for all tasks to complete
					wait(cves_details)
				except Exception as ie:
					logging.exception(f"Exception in main_post thread: {ie}")

			for t in threads:
				t.join()
			logging.info(f'POST execution details:: successful count: {len(output)}, failed in processing: {len(failed)}, unknown count: {unknown_len}')
			logging.info(f'List of unknown CVEs: {unknown}')
			end_time = int(time.time())
			logging.info(f'End time of execution: {end_time} and total_execution_time: {end_time - start_time} seconds')
			output_filename = "output" + os.path.sep + vulnfilename
			sys.stdout.write('\r')
			sys.stdout.flush()
			with open(output_filename + '.html', 'w', encoding='utf-8') as static_content:
				static_content.write(template.render(cve_data=output))
			if need_csv:
				write_csv(output_filename)
			logging.info(f"Output file {output_filename + '.html'} written!")
			print(f"\n\nExecution completed, please check the output file {output_filename + '.html'}!")
	except SystemExit:
		print('\n\rExiting script: sys.exit(1)')
		sys.exit(1)
	except Exception as e:
		logging.exception(f"Execution failed with reason:\n{e}", exc_info=True)
		print(f"Execution failed with reason:\n{e}")
		traceback.print_stack()

def load_template():
	global template
	env = Environment(loader=FileSystemLoader('templates'))
	template = env.get_template("mave_output.html")


def parse_args():
	global need_csv, vulnfile, vulnfilename, proxy_pass, max_threads
	parser = argparse.ArgumentParser()
	parser.add_argument('-i', dest='input_file', type=str, help="REQUIRED: File name with extn to read as an input", default="", required=False)
	parser.add_argument('-csv', dest='csv_output_flag', type=str, help="OPTIONAL: A flag 'y' or 'n' showing if a csv output is required", default='n', required=False)
	parser.add_argument('-p', dest='proxy_pass', type=str, help="OPTIONAL: Authentication password for proxy connection", default='nopass', required=False)
	parser.add_argument('-th', dest='max_thread', type=int, help="OPTIONAL: Number of max_threads that we want the system to spawn", default='500', required=False)
	args = parser.parse_args()
	vulnfile = args.input_file
	proxy_pass = args.proxy_pass
	need_csv = False
	if "" == vulnfile:
		parser.print_help()
		exit(0)
	if "y" == args.csv_output_flag.lower():
		need_csv = True
	if MAX_THREAD_CONST != args.max_thread:
		max_threads = args.max_thread
		if max_threads > MAX_THREAD_CONST:
			max_threads = MAX_THREAD_CONST
	right_index = vulnfile.rindex('.')
	vulnfilename = vulnfile[0:right_index]

def setup_logs():
	global log_file
	global start_time
	start_time = int(time.time())
	log_file = "logs" + os.path.sep + vulnfilename + "_" + str(start_time) + ".log"
	logging.basicConfig(filename=log_file, level=logging.INFO, format='%(levelname)s --> %(asctime)s: %(message)s', datefmt='%m/%d/%Y %H:%M:%S', filemode='a')
	logging.info(f'Start time of execution: {start_time}')

def check_for_commas(input):
	if COMMA in input:
		return '"' + input + '"'
	else:
		return input

def write_csv(output_filename):
	with open(output_filename + '.csv', 'w', encoding='utf-8', newline='\n') as csv_content:
		csv_content.write("CveId,ExploitRating,RiskRating,UserInteraction,AssociatedActors,AssociatedMalware,Title,ExploitationVector,PublishedDate,DateOfDisclosure,WasZeroDay,V3_BaseScore,V3_TemporalScore,V2_BaseScore,V2_TemporalScore")
		csv_content.write("\n")
		for cve_data in output:
			for key in cve_data:
				if "CveId" == key:
					if cve_data[key] is not None:
						if ":" in str(cve_data[key]):
							csv_content.write(str(cve_data[key])[:str(cve_data[key]).index(":")])
						else:
							csv_content.write(str(cve_data[key]))
				elif "AssociatedActors" == key or "AssociatedMalware" == key:
					csv_content.write(",")
					for actors in cve_data[key]:
						csv_content.write(check_for_commas(str(actors['Name']))+"; ")
				elif "ExploitationVector" == key:
					csv_content.write(",")
					for exploit_vector in cve_data[key]:
						csv_content.write(check_for_commas(exploit_vector)+"; ")
				else:
					csv_content.write("," + check_for_commas(str(cve_data[key])))
			csv_content.write("\n")
		logging.info(f"CSV output file {output_filename + '.csv'} written!")

if __name__ == "__main__":
	signal.signal(signal.SIGINT, signal_handler)
	main_post()
