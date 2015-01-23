from __future__ import with_statement
from fabric.api import *
from fabric.contrib.files import *
import ansible.runner
import ansible.playbook
from ansible import callbacks
from ansible import utils
import stick_const
import errno
import sys
from multiprocessing import Process

import ansible.constants as C
C.HOST_KEY_CHECKING = False

env.reject_unknown_hosts = False

#==============================================================================
#
# Fact Gathering
#
#==============================================================================


def profile_host(host):
	mem_result = execute(_check_mem_advail, hosts=host)
	threads_result = execute(_check_num_threads, hosts=host)
	disk_free_result = execute(_check_disk_free, hosts=host)
	admin_net_result = execute(_check_admin_network, hosts=host)

	return {"mem": mem_result[host], "threads": threads_result[host], "disk": disk_free_result[host], "has_admin": admin_net_result[host] }


def _check_mem_advail():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('vmstat -p M| awk \'(NR==2){for(i=1;i<=NF;i++)if($i=="free"){getline; print $i}}\'')
		match = re.search(r'^[0-9]+$', result)
		if match:                      
		 	return int(match.group())/100000
		else:
			return None


def _check_num_threads():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('psrinfo|wc -l|tr -d \' \'')
		match = re.search(r'^[0-9]+$', result)
		if match:                      
		 	return int(match.group())
		else:
			return None



def _check_disk_free():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('df -k /zones | awk \'(NR==2){print $4}\'')
		match = re.search(r'^[0-9]+$', result)
		if match:                      
		 	return int(match.group())/1000000
		else:
			return None

def _check_admin_network():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('sysinfo -p | grep Names | awk -F= \'{print $2}\' | grep "^\'admin\'$" | wc -l')
		match = re.search(r'^[0-9]+$', result)
		if match:                      
		 	if int(match.group()) == 1:
		 		return True
		 	else:
		 		return False
		else:
			return False




#==============================================================================
#
# VM Deployment
#
#==============================================================================

def create_first_fifo_zone(host):
	try:
		execute(_update_image, hosts=host)
		execute(_import_image, hosts=host)
		execute(_transfer_vm_def, hosts=host)
		return execute(_create_vm, hosts=host)
	except VmCreationException:
		return False
	return False



def _update_image():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		run('imgadm update')


def _import_image():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		run('imgadm import ' + stick_const.base64_img_uuid)


def _transfer_vm_def():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		put('tmp/fifo_vm.json', '/opt/fifo_vm.json')	


def _create_vm():
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		create_result = run('vmadm create -f /opt/fifo_vm.json')
		create_result_vmid = re.findall(r'^(?:Successfully created VM) ([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', create_result)
		if len(create_result_vmid) < 1:
			print create_result
			raise VmCreationException()
			return False
		else:
			return create_result_vmid[0]
			



#==============================================================================
#
# Local Go-Fetch Deployment
#
#==============================================================================

def deploy_fetch(local_go_fetch_dir, sniffle_params, snarl_params, howl_params, wiggle_params, chunter_params):
#def deploy_fetch(local_go_fetch_dir, sniffle_params):
	_clone_master(local_go_fetch_dir)
	apply_properties(local_go_fetch_dir, "fifo-sniffle", sniffle_params)
	apply_properties(local_go_fetch_dir, "fifo-snarl", snarl_params)
	apply_properties(local_go_fetch_dir, "fifo-howl", howl_params)
	apply_properties(local_go_fetch_dir, "fifo-wiggle", wiggle_params)
	apply_properties(local_go_fetch_dir, "fifo-chunter", chunter_params)



def _clone_master(local_go_fetch_dir):
	repo_location = local_go_fetch_dir + '/fetch'
	try:
		os.makedirs(repo_location)
	except OSError, e:
	    if e.errno != errno.EEXIST:
	        raise e
	    else:
	    	print "It looks like fetch is already deployed. Aborting download..."

	local("git clone https://github.com/Go-Fetch/Fetch.git " + repo_location )
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-sniffle.git")
	_create_playbook_for_role(repo_location, 'fifo-sniffle')
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-snarl.git")
	_create_playbook_for_role(repo_location, 'fifo-snarl')
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-howl.git")
	_create_playbook_for_role(repo_location, 'fifo-howl')
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-wiggle.git")
	_create_playbook_for_role(repo_location, 'fifo-wiggle')
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-jingles.git")
	_create_playbook_for_role(repo_location, 'fifo-jingles')
	local("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-chunter.git")
	_create_playbook_for_role(repo_location, 'fifo-chunter')


'''

	deploy_fetch_t1  = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-sniffle.git",) )
	deploy_fetch_t2  = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-sniffle',) )
	deploy_fetch_t3  = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-snarl.git",) )
	deploy_fetch_t4  = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-snarl',) )
	deploy_fetch_t5  = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-howl.git",) )
	deploy_fetch_t6  = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-howl',) )
	deploy_fetch_t7  = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-wiggle.git",) )
	deploy_fetch_t8  = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-wiggle',) )
	deploy_fetch_t9  = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-jingles.git",) )
	deploy_fetch_t10 = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-jingles',) )
	deploy_fetch_t11 = Process(target=local, args=("cd " + repo_location + "/roles; git submodule add https://github.com/Go-Fetch/fifo-chunter.git",) )
	deploy_fetch_t12 = Process(target=_create_playbook_for_role, args=(repo_location, 'fifo-chunter',) )



	deploy_fetch_t1.start()
	deploy_fetch_t2.start()
	deploy_fetch_t3.start()
	deploy_fetch_t4.start()
	deploy_fetch_t5.start()
	deploy_fetch_t6.start()
	deploy_fetch_t7.start()
	deploy_fetch_t8.start()
	deploy_fetch_t9.start()
	deploy_fetch_t10.start()
	deploy_fetch_t11.start()
	deploy_fetch_t12.start()


	deploy_fetch_t1.join()
	deploy_fetch_t2.join()
	deploy_fetch_t3.join()
	deploy_fetch_t4.join()
	deploy_fetch_t5.join()
	deploy_fetch_t6.join()
	deploy_fetch_t7.join()
	deploy_fetch_t8.join()
	deploy_fetch_t9.join()
	deploy_fetch_t10.join()
	deploy_fetch_t11.join()
	deploy_fetch_t12.join()

'''



#==============================================================================
#
# Ansible Actions
#
#==============================================================================

def apply_role(local_go_fetch_dir, role_name, host):

	from tempfile import NamedTemporaryFile

	temp = NamedTemporaryFile(delete=False)

	temp.write("[" + role_name + "-nodes]\n")
	temp.write(host + " ansible_connection=ssh  ansible_ssh_user=root ansible_python_interpreter=/opt/local/bin/python2.7 \n")
	temp.close()

	stats = callbacks.AggregateStats()
	playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
	runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

	pb = ansible.playbook.PlayBook(
	    playbook= local_go_fetch_dir + "/" + role_name + ".yml",
	    stats=stats,
	    callbacks=playbook_cb,
	    runner_callbacks=runner_cb,
	    host_list=temp.name
	)

	pb.run()  # This runs the playbook


def create_hypervisor_inventory(local_go_fetch_dir, hypervisors):
	inventory_file_name = local_go_fetch_dir + '/inventory/hypervisors'
	inventory_file = open(inventory_file_name, 'w')
	inventory_file.write('[hypervisors]\n')
	for hypervisor in hypervisors:
		inventory_file.write(hypervisor + ' ansible_connection=ssh  ansible_ssh_user=root ansible_python_interpreter=/opt/local/bin/python2.7\n')

	inventory_file.write('\n[fifo-chunter-nodes:children]\n')
	inventory_file.write('hypervisors\n')
	inventory_file.close()


def run_playbook(playbook_name, inventory_file):
	stats = callbacks.AggregateStats()
	playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
	runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

	pb = ansible.playbook.PlayBook(
	    playbook= playbook_name,
	    stats=stats,
	    callbacks=playbook_cb,
	    runner_callbacks=runner_cb,
	    host_list=inventory_file
	)

	pb.run()  # This runs the playbook


def run_playbook_with_pass(playbook_name, inventory_file, password):
	stats = callbacks.AggregateStats()
	playbook_cb = callbacks.PlaybookCallbacks(verbose=utils.VERBOSITY)
	runner_cb = callbacks.PlaybookRunnerCallbacks(stats, verbose=utils.VERBOSITY)

	pb = ansible.playbook.PlayBook(
	    playbook= playbook_name,
	    stats=stats,
	    callbacks=playbook_cb,
	    runner_callbacks=runner_cb,
	    host_list=inventory_file,
	    remote_pass=password
	)

	pb.run()  # This runs the playbook
	


#==============================================================================
#
# Fifo Actions
#
#==============================================================================


def create_fifo_user(fifo_host, user_name, password, rights="...", realm="default"):
	new_user_result = execute(_fifo_new_user, realm, user_name, hosts=fifo_host)
	grant_user_result = execute(_fifo_grant, realm, user_name, rights, hosts=fifo_host)
	if grant_user_result == None:
		return None
	if  execute(_fifo_set_password, realm, user_name, password, hosts=fifo_host):
		return new_user_result
	return None




def _fifo_new_user(realm, user_name):
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		create_result = run('fifoadm users add ' + realm + ' ' + user_name)
		create_result_userid = re.findall(r'([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', create_result)
		if len(create_result_userid) < 1:
			return False
		else:
			return create_result_userid[0]


def _fifo_grant(realm, user_name, rights):
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('fifoadm users grant ' + realm + ' ' + user_name + ' ' + rights)
		match = re.search(r'^Granted', result)
		if match:                      
		 	return True
		else:
			return None

def _fifo_set_password(realm, user_name, password):
	with settings(
		hide('warnings', 'running', 'stdout', 'stderr'),
		warn_only=True
	):
		result = run('fifoadm users passwd ' + realm + ' ' + user_name + ' ' + password)
		match = re.search(r'^Password successfully changed', result)
		if match:                      
		 	return True
		else:
			return None





def profile_host(host):
	mem_result = execute(_check_mem_advail, hosts=host)
	threads_result = execute(_check_num_threads, hosts=host)
	disk_free_result = execute(_check_disk_free, hosts=host)
	admin_net_result = execute(_check_admin_network, hosts=host)

	return {"mem": mem_result[host], "threads": threads_result[host], "disk": disk_free_result[host], "has_admin": admin_net_result[host] }





#==============================================================================
#
# Utils
#
#==============================================================================

def apply_properties(local_go_fetch_dir, repo_name, prop_list):
	for key, value in prop_list.iteritems(): 
		_repo_set_var(local_go_fetch_dir, repo_name, key, value)

def _repo_set_var(local_go_fetch_dir, repo_name, var_name, var_value):
	var_file = local_go_fetch_dir + '/fetch/roles/' + repo_name + '/vars/main.yml'

	f1 = open(var_file, 'r')
	f2 = open(var_file + '.tmp', 'w')

	for line in f1:
	    f2.write(line.replace("<<" + var_name + ">>", var_value))

	f1.close()
	f2.close()
	os.remove(var_file)
	os.rename(var_file + ".tmp", var_file)

def _create_playbook_for_role(fetch_dir, role_name):
	playbook_file_name = fetch_dir + '/' + role_name + '.yml'
	playbook_file = open(playbook_file_name, 'w')
	playbook_file.write('- hosts: ' + role_name + '-nodes\n')
	playbook_file.write('  roles:\n')
	playbook_file.write('    - ' + role_name + '\n')
	playbook_file.close()


def ssh_login(host, username, password):
	env.user = username
	env.password = password
	execute(_ssh_login, hosts=host)


def _ssh_login():
		run('echo " " > /dev/null')



#==============================================================================
#
# Exceptions
#
#==============================================================================


class VmCreationException(Exception):
    pass


		
