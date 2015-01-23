#!/usr/bin/env python

import sys
if not sys.version_info[:2] == (2, 7):
	print "Error: Requires Python 2.7"
	print ""
	sys.exit(0)

import os
import re
import getpass
import string
import random
import readline
import imp
from multiprocessing import Process

sys.path.append("lib")
from stick_strings import *
import stick_actions
import stick_templates
import stick_utility
import stick_const

sys.path.append("deps/netaddr-0.7.13-py2.7.egg")
from netaddr import *




prompt = '> '

temp_dir = "tmp"

if not os.path.exists(temp_dir):
    os.makedirs(temp_dir)

for the_file in os.listdir(temp_dir):
    file_path = os.path.join(temp_dir, the_file)
    try:
        if os.path.isfile(file_path):
            os.unlink(file_path)
    except Exception, e:
        None




def main():
	logo()

	run_conf = {}




	error = False
	IP_Net = None

	ansible_path = stick_utility.which('ansible')
	pyfi_path = stick_utility.which('fifo')
	git_path = stick_utility.which('git')

	if ansible_path == None:
		string_ansible_install_instructions()
		error = True
		
	if pyfi_path == None:
		string_pyfi_install_instructions()
		error = True

	if git_path == None:
		string_git_install_instructions()
		error = True

	try:
	    imp.find_module('fabric')
	except ImportError:
		string_fabric_install_instructions()
		error = True

	if error:
		sys.exit(0)




	string_stick_init_welcome()
	string_explain_admin_network()

	new_line()
	done = False
	while not done:
		string_prompt_hypervisors()
		input_hypervisors = raw_input(prompt)
		hypervisors_list = re.findall(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',input_hypervisors)
		if len(hypervisors_list) < 1:
			new_line()
			string_invalid_input()
		else:
			string_verify_list()
			for hypervisor in hypervisors_list:
				print hypervisor
			string_prompt_ok()
			input_ok = raw_input(prompt)
			if input_ok == "y":
				run_conf['hypervisors'] = hypervisors_list
				done = True


	new_line()
	done = False
	while not done:
		string_prompt_admin_network_ip()
		input_admin_network_ip = raw_input(prompt)
		if re.match(r'^(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)(/(3[012]|[12]?[0-9])))$', input_admin_network_ip):
			IP_Net = IPNetwork(input_admin_network_ip)
			run_conf['IP_Net'] =  IP_Net
			done = True
		else:
			new_line()
			string_invalid_input()

	new_line()
	done = False
	while not done:
		string_prompt_admin_network_vlan()
		input_admin_network_vlan = raw_input(prompt)
		if re.match(r'^(40[0-9][0-4]|[1-3][0-9][0-9][0-9]|[0-9][0-9][0-9]|[0-9][0-9]|[0-9])$', input_admin_network_vlan):
			run_conf['admin_network_vlan'] =  input_admin_network_vlan
			done = True
		else:
			new_line()
			string_invalid_input()


	new_line()
	done = False


	new_line()
	done = False
	while not done:
		string_prompt_admin_network_start()
		input_admin_network_start = raw_input(prompt)
		admin_network_start = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',input_admin_network_start)
		if admin_network_start == None:
			new_line()
			string_invalid_input()
		elif not IPAddress(admin_network_start.group()) in IP_Net:
			new_line()
			print "The given address is not in the network: " + str(IP_Net) + "."
		else:
			run_conf['admin_network_start'] =  admin_network_start.group()
			done = True


	new_line()
	done = False
	while not done:
		string_prompt_admin_network_end()
		input_admin_network_end = raw_input(prompt)
		admin_network_end = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',input_admin_network_end)
		if admin_network_end == None:
			new_line()
			string_invalid_input()
		elif not IPAddress(admin_network_end.group()) in IP_Net:
			new_line()
			print "The given address is not in the network: " + str(IP_Net) + "."
		else:
			run_conf['admin_network_end'] =  admin_network_end.group()
			done = True


	new_line()
	done = False
	while not done:
		string_prompt_admin_network_gateway()
		input_admin_network_gateway = raw_input(prompt)
		admin_network_gateway = re.match(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',input_admin_network_gateway)
		if admin_network_gateway == None:
			new_line()
			string_invalid_input()
		elif not IPAddress(admin_network_gateway.group()) in IP_Net:
			new_line()
			print "The given address is not in the network: " + str(IP_Net) + "."
		else:
			run_conf['admin_network_gateway'] =  admin_network_gateway.group()
			done = True



	new_line()
	done = False
	while not done:
		string_prompt_admin_network_resolv()
		input_resolvrs = raw_input(prompt)
		resolvrs_list = re.findall(r'((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))',input_resolvrs)
		if len(resolvrs_list) < 1:
			if not input_resolvrs:
				resolvrs_list = ['8.8.8.8', '8.8.4.4']
				done = True
			else:
				new_line()
				string_invalid_input()
		else:
			string_verify_list()
			for resolvr in resolvrs_list:
				print resolvr
			string_prompt_ok()
			input_ok = raw_input(prompt)
			if input_ok == "y":
				done = True

		run_conf['resolvrs_list'] =  resolvrs_list



	new_line()
	string_explain_authentication()

	new_line()
	done = False
	while not done:
		string_prompt_ssh_key()
		input_ssh_key = raw_input(prompt)
		if not input_ssh_key:
			input_ssh_key = prompt_ssh_key()
		if input_ssh_key and os.path.isfile(input_ssh_key):
			run_conf['ssh_key'] =  input_ssh_key
			done = True
		else:
			new_line()
			string_invalid_input()

#
#  TODO: It would be good to validate the file is actually a ssh pub key. http://stackoverflow.com/questions/2494450/ssh-rsa-public-key-validation-using-a-regular-expression
#


	new_line()
	done = False
	while not done:
			pw1 = getpass.getpass(prompt=string_prompt_admin_password())
			pw2 = getpass.getpass(prompt=string_prompt_verify_password())
			if pw1 == pw2 and pw1:
				run_conf['admin_user_password'] =  pw1
				done = True
			else:
				new_line()
				string_passwords_dont_match()
				new_line()

	new_line()
	string_explain_cookie()

	new_line()
	string_prompt_cookie()
	cookie_input = raw_input(prompt)
	if not cookie_input:
		run_conf['cookie'] = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(20))
	else:
		run_conf['cookie']  = cookie_input

	new_line()
	explain_point_of_no_return()
	new_line()

	

	print "Hypervisors: \t\t %s" % (run_conf['hypervisors'])
	print "Admin Network: \t\t %s" % (run_conf['IP_Net'])
	print "Admin Network Vlan: \t %s" % (run_conf['admin_network_vlan'])
	print "Admin Network Gateway: \t %s" % (run_conf['admin_network_gateway'])
	print "Admin Network DNS: \t %s" % (run_conf['resolvrs_list'])
	print "First Assignable IP: \t %s" % (run_conf['admin_network_start'])
	print "Last Assignable IP: \t %s" % (run_conf['admin_network_end'])
	print "Public SSH Key: \t %s" % (run_conf['ssh_key'])

	new_line()
	print "Accept (y/n)"
	input_ok = raw_input(prompt)
	if not (input_ok == "y" or input_ok == "Y"):
		print "Aborting... "
		new_line()
		sys.exit(0)
		

#
#  TODO!!!!
#
#   CHECK IF CHUNTER EXIST ON HYPER AND IF SO THEN ABORT
#
#

#
#
#  Download Go-Fetch to local computer and get all needed repos
#
#


	sniffle_params = {'sniffle_cookie': run_conf['cookie']}
	snarl_params = {'snarl_cookie': run_conf['cookie']}
	howl_params = {'howl_cookie': run_conf['cookie']}
	wiggle_params = {'wiggle_cookie': run_conf['cookie']}
	chunter_params = {'chunter_cookie': run_conf['cookie']}
	stick_actions.deploy_fetch(run_conf['fetch_location'], sniffle_params, snarl_params, howl_params, wiggle_params, chunter_params)


#
#
#  Probe first hypervisor, if acceptable create primary fifo zone
#
#
	
	new_line()
	string_explain_smartos_passwrd()

	profiling_results = stick_actions.profile_host("root@" + run_conf['hypervisors'][0])

	if(profiling_results["mem"] < stick_const.hyper_min_ram or  profiling_results["disk"] < stick_const.hyper_min_disk):
		print "There are insufficient resources on the first hypervisor for the first Fifo node. "
		print "If you have another hypervisor with more resouces please put it first in the list."
		print "Aborting... (No changes where made)"
		new_line()
		sys.exit(0)
	if profiling_results["has_admin"] == False:
		print "There is no network on the first hypervisor with the tag \"Admin\". This must exist!"
		print "Aborting... (No changes where made)"
		new_line()
		sys.exit(0)


	stick_templates.generate_vm("fifo.1", run_conf['resolvrs_list'], run_conf['admin_network_vlan'], 
			run_conf['admin_network_start'], run_conf['admin_network_gateway'], str(run_conf['IP_Net'].netmask), run_conf['ssh_key'])

	if not stick_actions.create_first_fifo_zone("root@" + run_conf['hypervisors'][0]):
		print "There was an error createing the first machine."
		print "Aborting... Some changes possibly made to hypervisor: " + run_conf['hypervisors'][0]
		new_line()
		sys.exit(0)




	# Deploy Chunter. This is ok to thread because it has no deps.

	def deploy_chunter(fetch_install_dir, hypervisors):
		stick_actions.create_hypervisor_inventory(fetch_install_dir, hypervisors)
		stick_actions.run_playbook_with_pass(fetch_install_dir + '/hypervisors.yml', fetch_install_dir + '/inventory/hypervisors', 'password')
		stick_actions.run_playbook_with_pass(fetch_install_dir + '/fifo-chunter.yml', fetch_install_dir + '/inventory/hypervisors', 'password')


#	for hypervisor in run_conf['hypervisors']:
#			stick_actions.ssh_login(hypervisor, "root", "password")

	deploy_chunter_t1 = Process(target=deploy_chunter, args=(run_conf['fetch_location'] + "/fetch", run_conf['hypervisors'],) )
	deploy_chunter_t1.start()	



#
#
#  Deploy Fifo to the primary zone
#
#

#
# TODO: jperkin says this may not be safe. more testing need. will continute to use untill bug report
#

	stick_actions.apply_role(run_conf['fetch_location'] + "/fetch", "fifo-sniffle", run_conf['admin_network_start'])

	deploy_first_zone_t1 = Process(target=stick_actions.apply_role, args=(run_conf['fetch_location'] + "/fetch", "fifo-snarl", run_conf['admin_network_start'],) )
	deploy_first_zone_t2 = Process(target=stick_actions.apply_role, args=(run_conf['fetch_location'] + "/fetch", "fifo-howl", run_conf['admin_network_start'],) )
	deploy_first_zone_t3 = Process(target=stick_actions.apply_role, args=(run_conf['fetch_location'] + "/fetch", "fifo-wiggle", run_conf['admin_network_start'],) )
	deploy_first_zone_t4 = Process(target=stick_actions.apply_role, args=(run_conf['fetch_location'] + "/fetch", "fifo-jingles", run_conf['admin_network_start'],) )

	deploy_first_zone_t1.start()
	deploy_first_zone_t2.start()
	deploy_first_zone_t3.start()
	deploy_first_zone_t4.start()

	deploy_first_zone_t1.join()
	deploy_first_zone_t2.join()
	deploy_first_zone_t3.join()
	deploy_first_zone_t4.join()

	#stick_actions.apply_role("/Users/kevinmeziere/fetch", "fifo-snarl", run_conf['admin_network_start'])
	#stick_actions.apply_role("/Users/kevinmeziere/fetch", "fifo-howl", run_conf['admin_network_start'])
	#stick_actions.apply_role("/Users/kevinmeziere/fetch", "fifo-wiggle", run_conf['admin_network_start'])
	#stick_actions.apply_role("/Users/kevinmeziere/fetch", "fifo-jingles", run_conf['admin_network_start'])




	stick_actions.create_fifo_user(run_conf['admin_network_start'], "root", run_conf['admin_user_password'])


	# Make sure chunter is done deploying
	deploy_chunter_t1.join()


# create cluster - via fifo api
# create vms - via fifo api

# install fifo roles - via ansible
# start services - via ansible
# join cluster - via fabric





def prompt_ssh_key():
	i = 1
	pub_keys = {}
	for path in os.listdir(os.path.expanduser("~") + "/.ssh"):
			if os.path.splitext(path)[1] == '.pub':
				pub_keys[i]= path
				i += 1
	if len(pub_keys) > 0:
		print "Please select a key from the following [1]:"
		for key, path in pub_keys.iteritems():
			print str(key) + ".  " + path
		input_key_section = raw_input(prompt)
		if not input_key_section:
			return os.path.expanduser("~") + "/.ssh/" + pub_keys[1]
		try: 
			if int(input_key_section) in pub_keys:
				return os.path.expanduser("~") + "/.ssh/" + pub_keys[int(input_key_section)]
			else:
				return None
		except ValueError:
			return None
	else:
		print "No keys found in /.ssh - You will need to manually input your public key file name."
		return None


if __name__ == "__main__":
	try:
		#debug()
		main()
	except KeyboardInterrupt:
		new_line()
		sys.exit(0)

		