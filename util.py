#!/usr/bin/env pythen

"""ShutIt utility functions.
"""

#The MIT License (MIT)
#
#Copyright (C) 2014 OpenBet Limited
#
#Permission is hereby granted, free of charge, to any person obtaining a copy of
#this software and associated documentation files (the "Software"), to deal in
#the Software without restriction, including without limitation the rights to
#use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
#of the Software, and to permit persons to whom the Software is furnished to do
#so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#ITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
#THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

import sys
import argparse
import os
import stat
from ConfigParser import RawConfigParser
import time
import re
import imp
import shutit_global
from shutit_module import ShutItModule
import pexpect
import socket
import textwrap
import json
import binascii
import base64
import subprocess
import getpass
import StringIO
import copy
import hashlib
from shutit_module import ShutItFailException

_default_cnf = '''
################################################################################
## Default core config file for ShutIt.
#  If this file is in the core of ShutIt it should only
#  ever be changed by the maintainer/BDFL.
#  If it's been copied into a module, then the maintainer
#  of that module only should be changing it.
#  If you are a developer on SI or the module, change the
#  config specific to your run (ie configs/<hostname>_<username>.cnf)
#
#  Submit a pull request to the maintainer if you want the
#  default.cnf changed.
################################################################################

# Details relating to the container you are building itself
[container]
# Root password for the container - replace with your chosen password
# If left blank, you will be prompted for a password
password:YOUR_CONTAINER_PASSWORD
# Hostname for the container - replace with your chosen container name
hostname:
force_repo_work:no
locale:en_US.UTF-8
# space separated list of ports to expose
# e.g. "ports:2222:22 8080:80" would expose container ports 22 and 80 as the
# host's 2222 and 8080
ports:
# Name to give the container. Empty means "let docker default a name".
name:
# Whether to remove the container when finished.
rm:no

# Information specific to the host on which the build runs.
[host]
# Folder with files you want to copy from in your build.
# Often a good idea to have a central folder for this per host
# in your /path/to/shutit/configs/`hostname`_`username`.cnf
# If set to blank, then defaults to /path/to/shutit/resources (preferred)
# If set to "resources", then defaults to the resources folder in the cwd.
resources_dir:
# Docker executable on your host machine
docker_executable:docker.io
# space separated list of dns servers to use
dns:
# Password for the username above on the host (only needed if sudo is needed)
password:
# Log file - will be set to 0600 perms, and defaults to /tmp/<YOUR_USERNAME>_shutit_log_<timestamp>
# A timestamp will be added to the end of the filename.
logfile:

# Repository information
[repository]
# Whether to tag
tag:no
# Whether to suffix the date to the tag
suffix_date:yes
# Suffix format (default is epoch seconds (%s), but %Y%m%d_%H%M%S is an option if the length is ok with the index)
suffix_format:%s
# tag name
name:my_repository_name
# Whether to tar up the docker image exported
export:no
# Whether to tar up the docker image saved
save:no
# Whether to push to the server
push:no
# User on registry to namespace repo - can be set to blank if not docker.io
user:
#Must be set if do_repository_work is true/yes and user is not blank
password:YOUR_INDEX_PASSWORD_OR_BLANK
#Must be set if do_repository_work is true/yes and user is not blank
email:YOUR_INDEX_EMAIL_OR_BLANK
# repository server
# make blank if you want this to be sent to the main docker index on docker.io
server:

# Root setup script
# Each module should set these in a config
[shutit.tk.setup]
build:yes
# Modules may rely on the below settings, only change for debugging. Do not rely
# on these configs being stable.
do_update:yes

# Aspects of build process
[build]
build_log:no
# Run container in privileged mode
privileged:no
# lxc-conf arg, eg
#lxc_conf:lxc.aa_profile=unconfined
lxc_conf:
# Allowed images json-list, eg ["ubuntu:12.04"], each matched on
# an OR basis with the image base.
# 'any' is a special value meaning any image is ok, and is the default.
# It's recommended this is locked down as far as possible.
# NB each image must be in double quotes.
allowed_images:["any"]
# Base image can be over-ridden by --image_tag defaults to this.
base_image:ubuntu:12.04
'''

class LayerConfigParser(RawConfigParser):

	def __init__(self):
		RawConfigParser.__init__(self)
		self.layers = []

	def read(self, filenames):
		if type(filenames) is not list:
			filenames = [filenames]
		for filename in filenames:
			cp = RawConfigParser()
			cp.read(filename)
			self.layers.append((cp, filename, None))
		return RawConfigParser.read(self, filenames)

	def readfp(self, fp, filename=None):
		cp = RawConfigParser()
		fp.seek(0)
		cp.readfp(fp, filename)
		self.layers.append((cp, filename, fp))
		fp.seek(0)
		ret = RawConfigParser.readfp(self, fp, filename)
		return ret

	def whereset(self, sec, name):
		for cp, filename, fp in reversed(self.layers):
			if cp.has_option(sec, name):
				return filename
		raise ShutItFailException('[%s]/%s was never set' % (sec, name))

	def reload(self):
		"""
		Re-reads all layers again. In theory this should overwrite all the old
		values with any newer ones.
		It assumes we never delete a config item before reload.
		"""
		oldlayers = self.layers
		self.layers = []
		for cp, filename, fp in oldlayers:
			if fp is None:
				self.read(filename)
			else:
				self.readfp(fp, filename)

	def remove_section(self, *args, **kwargs):
		raise NotImplementedError('Layer config parsers aren\'t directly mutable')
	def remove_option(self, *args, **kwargs):
		raise NotImplementedError('Layer config parsers aren\'t directly mutable')
	def set(self, *args, **kwargs):
		raise NotImplementedError('Layer config parsers aren\'t directly mutable')

def is_file_secure(file_name):
	"""Returns false if file is considered insecure, true if secure.
	If file doesn't exist, it's considered secure!
	"""
	if not os.path.isfile(file_name):
		return True
	file_mode = os.stat(file_name).st_mode
	if file_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
		return False
	return True


def colour(code, msg):
	"""Colourize the given string for a terminal.
	"""
	return '\033[%sm%s\033[0m' % (code, msg)


def get_config(cfg,module_id,option,default,boolean=False):
	"""Gets a specific config from the config files,
	allowing for a default.
	Handles booleans vs strings appropriately.
	"""
	if module_id not in cfg.keys():
		cfg[module_id] = {}
	if not cfg['config_parser'].has_section(module_id):
		cfg['config_parser'].add_section(module_id)
	if cfg['config_parser'].has_option(module_id,option):
		if boolean:
			cfg[module_id][option] = cfg['config_parser'].getboolean(module_id,option)
		else:
			cfg[module_id][option] = cfg['config_parser'].get(module_id,option)
	else:
		cfg[module_id][option] = default
		#cfg['config_parser'].set(module_id,default)

def get_configs(shutit,configs):
	"""Reads config files in, checking their security first
	(in case passwords/sensitive info is in them).
	"""
	cp       = LayerConfigParser()
	fail_str = ''
	files    = []
	for config_file in configs:
		if type(config_file) is tuple:
			continue
		if not is_file_secure(config_file):
			fail_str = fail_str + '\nchmod 0600 ' + config_file
			files.append(config_file)
	if fail_str != '':
		fail_str = 'Files are not secure, mode should be 0600. Running the following commands to correct:\n' + fail_str + '\n'
		# Actually show this to the user before failing...
		shutit.log(fail_str,force_stdout=True)
		shutit.log('\n\nDo you want me to run this for you? (input y/n)\n',force_stdout=True)
		if shutit.cfg['action']['serve'] or raw_input('') == 'y':
			for f in files:
				os.chmod(f,0600)
			return get_configs(shutit,configs)
		shutit.fail(fail_str)
	for config in configs:
		if type(config) is tuple:
			cp.readfp(config[1], filename=config[0])
		else:
			cp.read(config)
	return cp

def issue_warning(msg,wait):
	"""Issues a warning to stderr.
	"""
	print >> sys.stderr, msg
	time.sleep(wait)

# Manage config settings, returning a dict representing the settings
# that have been sanity-checked.
def get_base_config(cfg, cfg_parser):
	"""Responsible for getting core configuration from config files.
	"""
	cfg['config_parser'] = cp = cfg_parser
	# BEGIN Read from config files
	cfg['build']['privileged']                    = cp.getboolean('build','privileged')
	cfg['build']['lxc_conf']                      = cp.get('build','lxc_conf')
	cfg['build']['build_log']                     = cp.getboolean('build','build_log')
	cfg['build']['allowed_images']                = json.loads(cp.get('build','allowed_images'))
	cfg['build']['base_image']                    = cp.get('build','base_image')
	cfg['build']['build_db_dir']                  = '/root/shutit_build'
	cfg['container']['password']                  = cp.get('container','password')
	cfg['container']['hostname']                  = cp.get('container','hostname')
	cfg['container']['force_repo_work']           = cp.getboolean('container','force_repo_work')
	cfg['container']['locale']                    = cp.get('container','locale')
	cfg['container']['ports']                     = cp.get('container','ports')
	cfg['container']['name']                      = cp.get('container','name')
	cfg['container']['rm']                        = cp.getboolean('container','rm')
	cfg['host']['resources_dir']                  = cp.get('host','resources_dir')
	cfg['host']['docker_executable']              = cp.get('host','docker_executable')
	cfg['host']['dns']                            = cp.get('host','dns')
	cfg['host']['password']                       = cp.get('host','password')
	cfg['host']['logfile']                        = cp.get('host','logfile')
	cfg['repository']['name']                     = cp.get('repository','name')
	cfg['repository']['server']                   = cp.get('repository','server')
	cfg['repository']['push']                     = cp.getboolean('repository','push')
	cfg['repository']['tag']                      = cp.getboolean('repository','tag')
	cfg['repository']['export']                   = cp.getboolean('repository','export')
	cfg['repository']['save']                     = cp.getboolean('repository','save')
	cfg['repository']['suffix_date']              = cp.getboolean('repository','suffix_date')
	cfg['repository']['suffix_format']            = cp.get('repository','suffix_format')
	cfg['repository']['user']                     = cp.get('repository','user')
	cfg['repository']['password']                 = cp.get('repository','password')
	cfg['repository']['email']                    = cp.get('repository','email')
	# END Read from config files

	# BEGIN Standard expects
	# It's important that these have '.*' in them at the start, so that the matched data is reliablly 'after' in the
	# child object. Use these where possible to make things more consistent.
	# Attempt to capture any starting prompt (when starting)
	cfg['expect_prompts']['base_prompt']             = '\r\n.*[@#$]'
	# END Standard expects

	# BEGIN tidy configs up
	if cfg['host']['resources_dir'] == 'resources':
		cfg['host']['resources_dir'] = os.path.join(shutit_global.cwd, 'resources')
	elif cfg['host']['resources_dir'] == '':
		cfg['host']['resources_dir'] = os.path.join(shutit_global.shutit_main_dir, 'resources')
	if cfg['host']['logfile'] == '':
		logfile = os.path.join('/tmp/', 'shutit_log_' + cfg['build']['build_id'])
	else:
		logfile = logfile + '_' + cfg['build']['build_id']
	if cfg['build']['build_log']:
		cfg['build']['build_log'] = open(logfile,'a')
		# Lock it down to the running user.
		os.chmod(logfile,0600)
	if cfg['container']['docker_image'] == '':
		cfg['container']['docker_image'] = cfg['build']['base_image']
	# END tidy configs up

	# BEGIN warnings
	# Warn if something appears not to have been overridden
	warn = ''
	if cfg['container']['password'][:5] == 'YOUR_':
		warn = '# Found ' + cfg['container']['password'] + ' in your config, you may want to quit and override, eg put the following into your\n# ' + shutit_global.cwd + '/configs/' + socket.gethostname() + '_' + cfg['host']['real_user'] + '.cnf file (create if necessary):\n\n[container]\n#root password for the container\npassword:mycontainerpassword\n\n'
		issue_warning(warn,2)
	# FAILS begins
	# rm is incompatible with repository actions
	if cfg['container']['rm'] and (cfg['repository']['tag'] or cfg['repository']['push'] or cfg['repository']['save'] or cfg['repository']['export']):
		print("Can't have [container]/rm and [repository]/(push/save/export) set to true")
		sys.exit()
	if warn != '':
		issue_warning('Showing computed config. This can also be done by calling with sc:',2)
		shutit_global.shutit.log(print_config(cfg),force_stdout=True,code='31')
		time.sleep(1)
	# If build/allowed_images doesn't contain container/docker_image
	if 'any' not in cfg['build']['allowed_images'] and cfg['container']['docker_image'] not in cfg['build']['allowed_images']:
		print('Allowed images for this build are: ' + str(cfg['build']['allowed_images']) + ' but the configured image is: ' + cfg['container']['docker_image'])
		sys.exit()
	# FAILS ends
	if cfg['container']['password'] == '':
		cfg['container']['password'] = getpass.getpass(prompt='Input your container password: ')

# Returns the config dict
def parse_args(cfg):
	"""Responsible for parsing arguments.

	TODO: precendence

	Environment variables:
	SHUTIT_OPTIONS:
		Loads command line options from the environment (if set).
		Behaves like GREP_OPTIONS:
		- space separated list of arguments
		- backslash before a space escapes the space separation
		- backslash before a backslash is interpreted as a single backslash
		- all other backslashes are treated literally
		eg ' a\ b c\\ \\d \\\e\' becomes '', 'a b', 'c\', '\d', '\\e\'
		SHUTIT_OPTIONS is ignored if we are creating a skeleton
	"""
	cfg['host']['real_user_id'] = pexpect.run('id -u ' + cfg['host']['real_user']).strip()

	# These are in order of their creation
	actions = ['build','sc','depgraph','serve','skeleton']

	# Compatibility
	# Note that (for now) all of these compat functions work because we know
	# that there are no --options to shutit (as opposed to a subcommand)
	# COMPAT 2014-05-13 - let sc and depgraph have '--' prefix
	if '--sc' in sys.argv:
		sys.argv.remove('--sc')
		sys.argv[1:] = ['sc'] + sys.argv[1:]
	if '--depgraph' in sys.argv:
		sys.argv.remove('--depgraph')
		sys.argv[1:] = ['depgraph'] + sys.argv[1:]
	# COMPAT 2014-05-15 - let serve, sc and depgraph be specified anywhere in
	# arguments for backwards compatibility. Hopefully there's no setting
	# involving those words
	for action in ['serve', 'depgraph', 'sc']:
		try:
			sys.argv.remove(action)
			sys.argv[1:] = [action] + sys.argv[1:]
		except:
			pass
	# COMPAT 2014-05-15 - build is the default if there is no action specified
	# and we've not asked for help and we've called via 'shutit_main.py'
	if len(sys.argv) == 1 or (len(sys.argv) > 1 and sys.argv[1] not in actions
			and '-h' not in sys.argv and '--help' not in sys.argv
			and os.path.basename(sys.argv[0]) == 'shutit_main.py'):
		sys.argv.insert(1, 'build')

	# Pexpect documentation says systems have issues with pauses < 0.05
	def check_pause(value):
		ivalue = float(value)
		if ivalue < 0.05:
			raise argparse.ArgumentTypeError(
				"%s is an invalid pause (must be >= 0.05)" % value)
		return ivalue

	parser = argparse.ArgumentParser(description='ShutIt - a tool for managing complex Docker deployments')
	subparsers = parser.add_subparsers(dest='action', help='Action to perform. Defaults to \'build\'.')

	sub_parsers = dict()
	for action in actions:
		sub_parsers[action] = subparsers.add_parser(action)

	sub_parsers['skeleton'].add_argument('path', help='absolute path to new directory for module')
	sub_parsers['skeleton'].add_argument('module_name', help='name for your module')
	sub_parsers['skeleton'].add_argument('domain', help='arbitrary but unique domain for namespacing your module, eg com.mycorp')
	sub_parsers['skeleton'].add_argument('script', help='pre-existing shell script to integrate into module (optional)', nargs='?', default=None)
	sub_parsers['skeleton'].add_argument('--example', help='add an example implementation with model calls to ShutIt API', default=False, const=True, action='store_const')

	sub_parsers['build'].add_argument('--export', help='export to a tar file', const=True, default=False, action='store_const')
	sub_parsers['build'].add_argument('--save', help='save to a tar file', const=True, default=False, action='store_const')
	sub_parsers['build'].add_argument('--push', help='push to a repo', const=True, default=False, action='store_const')

	sub_parsers['sc'].add_argument('--history', help='show config history', const=True, default=False, action='store_const')

	for action in ['build','serve','depgraph','sc']:
		sub_parsers[action].add_argument('--config', help='Config file for setup config. Must be with perms 0600. Multiple arguments allowed; config files considered in order.',default=[], action='append')
		sub_parsers[action].add_argument('-s', '--set', help='Override a config item, e.g. "-s container rm no". Can be specified multiple times.', default=[], action='append', nargs=3, metavar=('SEC','KEY','VAL'))
		sub_parsers[action].add_argument('--image_tag', help='Build container using specified image - if there is a symbolic reference, please use that, eg localhost.localdomain:5000/myref',default='')
		sub_parsers[action].add_argument('-m','--shutit_module_path', default='.',help='List of shutit module paths, separated by colons. ShutIt registers modules by running all .py files in these directories.')
		sub_parsers[action].add_argument('--pause',help='Pause between commands to avoid race conditions.',default='0.05',type=check_pause)
		sub_parsers[action].add_argument('--debug',help='Show debug.',default=False,const=True,action='store_const')
		sub_parsers[action].add_argument('--interactive',help='Level of interactive. 0 = none, 1 = honour pause points and config prompting, 2 = query user on each module, 3 = tutorial mode',default='1')

	args_list = sys.argv[1:]
	if os.environ.get('SHUTIT_OPTIONS', None) and args_list[0] != 'skeleton':
		env_args = os.environ['SHUTIT_OPTIONS'].strip()
		# Split escaped backslashes
		env_args_split = re.split(r'(\\\\)', env_args)
		# Split non-escaped spaces
		env_args_split = [re.split(r'(?<!\\)( )', item) for item in env_args_split]
		# Flatten
		env_args_split = [item for sublist in env_args_split for item in sublist]
		# Split escaped spaces
		env_args_split = [re.split(r'(\\ )', item) for item in env_args_split]
		# Flatten
		env_args_split = [item for sublist in env_args_split for item in sublist]
		# Trim empty strings
		env_args_split = [item for item in env_args_split if item != '']
		# We know we don't have to deal with an empty env argument string
		env_args_list = ['']
		# Interpret all of the escape sequences
		for item in env_args_split:
			if item == ' ':
				env_args_list.append('')
			elif item == '\\ ':
				env_args_list[-1] = env_args_list[-1] + ' '
			elif item == '\\\\':
				env_args_list[-1] = env_args_list[-1] + '\\'
			else:
				env_args_list[-1] = env_args_list[-1] + item
		args_list[1:1] = env_args_list

	args = parser.parse_args(args_list)

	# What are we asking shutit to do?
	cfg['action']['show_config'] =   args.action == 'sc'
	cfg['action']['show_depgraph'] = args.action == 'depgraph'
	cfg['action']['serve'] =         args.action == 'serve'
	cfg['action']['skeleton'] =      args.action == 'skeleton'
	cfg['action']['build'] =         args.action == 'build'

	# This mode is a bit special - it's the only one with different arguments
	if cfg['action']['skeleton']:
		cfg['skeleton'] = {
			'path': args.path,
			'module_name': args.module_name,
			'domain': args.domain,
			'domainhash': str(get_hash(args.domain)),
			'script': args.script,
			'example': args.example
		}
		return

	shutit_home = cfg['shutit_home'] = os.path.expanduser('~/.shutit')
	# We're not creating a skeleton, so make sure we have the infrastructure
	# in place for a user-level storage area
	if not os.path.isdir(shutit_home):
		os.mkdir(shutit_home, 0o700)
	if not os.path.isfile(os.path.join(shutit_home, 'config')):
		os.close(os.open(
			os.path.join(shutit_home, 'config'),
			os.O_WRONLY | os.O_CREAT,
			0o600
		))

	# Persistence-related arguments.
	if cfg['action']['build']:
		cfg['repository']['push'] = args.push
		cfg['repository']['export'] = args.export
		cfg['repository']['save'] = args.save
	elif cfg['action']['show_config']:
		cfg['build']['cfghistory'] = args.history

	# Get these early for this part of the build.
	# These should never be config arguments, since they are needed before config is passed in.
	cfg['build']['debug'] = args.debug
	cfg['build']['interactive'] = int(args.interactive)
	cfg['build']['command_pause'] = float(args.pause)
	cfg['build']['extra_configs'] = args.config
	cfg['build']['config_overrides'] = args.set
	cfg['container']['docker_image'] = args.image_tag
	# Get module paths
	cfg['host']['shutit_module_paths'] = args.shutit_module_path.split(':')
	if '.' not in cfg['host']['shutit_module_paths']:
		if cfg['build']['debug']:
			shutit_global.shutit.log('Working directory path not included, adding...')
			time.sleep(1)
		cfg['host']['shutit_module_paths'].append('.')
	# Finished parsing args, tutorial stuff
	if cfg['build']['interactive'] >= 3:
		print textwrap.dedent("""\
			================================================================================
			SHUTIT - INTRODUCTION
			================================================================================
			ShutIt is a script that allows the building of static containers.
			allowing a high degree of flexibility and easy conversion from other build
			methods (eg bash scripts)

			It is configured through command-line arguments (see --help) and .cnf files.
			================================================================================


			================================================================================
			CONFIG
			================================================================================
			The config files are read in the following order:
			================================================================================
			""" + str(cfg['host']['shutit_module_paths']) + """
			""" + shutit_global.shutit_main_dir + """/configs/`hostname`_`whoami`.cnf
			    - Host- and username-specific config for this host.
			/path/to/this/shutit/module/configs/build.cnf
			    - Config specifying what should be built when this module is invoked.
			/your/path/to/<configname>.cnf
			    - Passed-in config (via --config, see --help)
			================================================================================
			Config items look like this:

			[section]
			name:value
			================================================================================

			""" + colour('31','[Hit return to continue]'))
		raw_input('')
		print textwrap.dedent("""\
			================================================================================
			MODULES
			================================================================================
			Each module (which is a .py file) has a lifecycle, "module_id" and "run_order".

			The lifecycle (briefly) is as follows:

			    foreach module:
			        remove all modules config'd for removal
			    foreach module:
			        build
			        tag
			            stop all modules already started
			            do repository work configured
			            start all modules that were stopped
			        start
			    foreach module:
			        test module
			    stop all modules already started
			    foreach module:
			        finalize module

			and these stages are run from the module code, returning True or False as
			appropriate.

			The module_id is a string that uniquely identifies the module.

			The run_order is a float that defines the order in which the module should be
			run relative to other modules.

			See """ + shutit_global.shutit_main_dir + """/shutit_module.py for more detailed documentation on these.
			================================================================================

			""" + colour('31','[Hit return to continue]'))
		raw_input('')
		print textwrap.dedent("""\
			================================================================================
			PAUSE POINTS
			================================================================================
			Pause points can be placed within the build, which is useful for debugging.
			This is used throughout this tutorial.
			When debugging, pause_points will output your keyboard input before you finish.
			This can help you build your build, as these commands can be pasted into the
			module you are developing easily.
			To escape a pause point, hit the "CTRL" and the "]" key simultaneously.
			================================================================================
			""" + colour('31','[Hit return to continue]'))
		raw_input('')

def load_configs(shutit):
	"""Responsible for loading config files into ShutIt.
	Recurses down from configured shutit module paths.
	"""
	cfg = shutit.cfg
	# Get root default config.
	configs = [('defaults', StringIO.StringIO(_default_cnf))]
	# Add the shutit global host- and user-specific config file.
	configs.append(os.path.join(shutit.shutit_main_dir,
		'configs/' + socket.gethostname() + '_' + cfg['host']['real_user'] + '.cnf'))
	configs.append(os.path.join(cfg['shutit_home'], 'config'))
	# Add the local build.cnf
	configs.append('configs/build.cnf')
	# Get passed-in config(s)
	for config_file_name in cfg['build']['extra_configs']:
		run_config_file = os.path.expanduser(config_file_name)
		if not os.path.isfile(run_config_file):
			print('Did not recognise ' + run_config_file +
					' as a file - do you need to touch ' + run_config_file + '?')
			sys.exit()
		configs.append(run_config_file)
	# Image to use to start off. The script should be idempotent, so running it
	# on an already built image should be ok, and is advised to reduce diff space required.
	if cfg['build']['interactive'] >= 3 or cfg['action']['show_config']:
		msg = ''
		for c in configs:
			if type(c) is tuple:
				c = c[0]
			msg = msg + '\t\n' + c
			shutit.log('\t' + c)
		if cfg['build']['interactive'] >= 3:
			print textwrap.dedent("""\n""") + msg + textwrap.dedent("""
				Looking at config files in the above order (even if they
				do not exist - you may want to create them).
				
				If you get a "Port already in use:" error,
				run:
					docker ps -a | grep -w <port> | awk '{print $1}' | xargs docker kill
					
				or
					sudo docker ps -a | grep -w <port> | awk '{print $1}' | xargs sudo docker kill
				""" + colour('31','[Hit return to continue]'))
			raw_input('')

	# Interpret any config overrides, write to a file and add them to the
	# list of configs to be interpreted
	if cfg['build']['config_overrides']:
		# We don't need layers, this is a temporary configparser
		override_cp = RawConfigParser()
		for o_sec, o_key, o_val in cfg['build']['config_overrides']:
			if not override_cp.has_section(o_sec):
				override_cp.add_section(o_sec)
			override_cp.set(o_sec, o_key, o_val)
		override_fd = StringIO.StringIO()
		override_cp.write(override_fd)
		override_fd.seek(0)
		configs.append(('overrides', override_fd))

	cfg_parser = get_configs(shutit,configs)
	get_base_config(cfg, cfg_parser)

def load_shutit_modules(shutit):
	"""Responsible for loading the shutit modules based on the configured moduleu
	paths.
	"""
	if shutit.cfg['build']['debug']:
		shutit.log('ShutIt module paths now: ')
		shutit.log(shutit.cfg['host']['shutit_module_paths'])
		time.sleep(1)
	for shutit_module_path in shutit.cfg['host']['shutit_module_paths']:
		load_all_from_path(shutit, shutit_module_path)

def print_config(cfg,hide_password=True,history=False):
	"""Returns a string representing the config of this ShutIt run.
	"""
	r = ''
	keys1 = cfg.keys()
	if keys1:
		keys1.sort()
	for k in keys1:
		if type(k) == str and type(cfg[k]) == dict:
			r = r + '\n[' + k + ']\n'
			keys2 = cfg[k].keys()
			if keys2:
				keys2.sort()
			for k1 in keys2:
					r = r + k1 + ':' 
					if hide_password and (k1 == 'password' or k1 == 'passphrase'):
						s = hashlib.sha512(cfg[k][k1]).hexdigest()
						i = 27
						while i > 0:
							i = i - 1
							s = hashlib.sha512(s).hexdigest()
						r = r + s
					else:
						if type(cfg[k][k1] == bool):
							r = r + str(cfg[k][k1])
						elif type(cfg[k][k1] == str):
							r = r + cfg[k][k1]
					r = r + '\n'
	return r

def set_pexpect_child(key,child):
	"""Set a pexpect child in the global dictionary by key.
	"""
	shutit_global.pexpect_children.update({key:child})

def get_pexpect_child(key):
	"""Get a pexpect child in the global dictionary by key.
	"""
	return shutit_global.pexpect_children[key]

def load_all_from_path(shutit, path):
	"""Dynamically imports files within the same directory (in the end, the path).
	"""
	#http://stackoverflow.com/questions/301134/dynamic-module-import-in-python
	if os.path.abspath(path) == shutit.shutit_main_dir:
		return
	if not os.path.exists(path):
		return
	for root, subFolders, files in os.walk(path):
		for fname in files:
			load_mod_from_file(shutit, os.path.join(root, fname))

def load_mod_from_file(shutit, fpath):
	"""Loads modules from a .py file into ShutIt if there are no modules from
	this file already.
	We expect to have a callable 'module/0' which returns one or more module
	objects.
	If this doesn't exist we assume that the .py file works in the old style
	(automatically inserting the module into shutit_global) or it's not a shutit
	module.
	"""
	fpath = os.path.abspath(fpath)
	file_ext = os.path.splitext(os.path.split(fpath)[-1])[-1]
	if file_ext.lower() != '.py':
		return
	# Do we already have modules from this file? If so we know we can skip.
	# Note that this attribute will only be set for 'new style' module loading,
	# this should be ok because 'old style' loading checks for duplicate
	# existing modules.
	# TODO: this is quadratic complexity
	existingmodules = [
		m for m in shutit.shutit_modules
		if getattr(m, '__module_file', None) == fpath
	]
	if len(existingmodules) > 0:
		return
	# Looks like it's ok to load this file
	if shutit.cfg['build']['debug']:
		shutit.log('Loading source for: ' + fpath)

	mod_name = base64.b32encode(fpath).replace('=', '')
	pymod = imp.load_source(mod_name, fpath)

	# Got the python module, now time to pull the shutit module(s) out of it.
	targets = [
		('module', shutit.shutit_modules), ('conn_module', shutit.conn_modules)
	]
	shutit.cfg['build']['source'] = {}
	for attr, target in targets:
		modulefunc = getattr(pymod, attr, None)
		# Old style or not a shutit module, nothing else to do
		if not callable(modulefunc):
			return
		modules = modulefunc()
		if type(modules) is not list:
			modules = [modules]
		for module in modules:
			setattr(module, '__module_file', fpath)
			ShutItModule.register(module.__class__)
			target.add(module)
			shutit.cfg['build']['source'][fpath] = open(fpath).read()


# Build report
def build_report(shutit,msg=''):
	"""Resposible for constructing a report to be output as part of the build.
	Retrurns report as a string.
	"""
	s = ''
	s = s + '################################################################################\n'
	s = s + '# COMMAND HISTORY BEGIN ' + shutit_global.cfg['build']['build_id'] + '\n'
	s = s + '################################################################################\n'
	s = s + get_commands(shutit)
	s = s + '# COMMAND HISTORY END ' + shutit_global.cfg['build']['build_id'] + '\n'
	s = s + '################################################################################\n'
	s = s + '################################################################################\n'
	s = s + '# BUILD REPORT FOR BUILD BEGIN ' + shutit_global.cfg['build']['build_id'] + '\n'
	s = s + '# ' + msg + '\n'
	s = s + '################################################################################\n'
	if shutit_global.cfg['build']['report'] != '':
		s = s + shutit_global.cfg['build']['report'] + '\n'
	else:
		s = s + '# Nothing to report\n'
	s = s + '# BUILD REPORT FOR BUILD END ' + shutit_global.cfg['build']['build_id'] + '\n'
	s = s + '################################################################################\n'
	return s

def get_commands(shutit):
	"""Gets command that have been run and have not been redacted.
	"""
	s = ''
	for c in shutit_global.shutit_command_history:
		s = s + c + '\n'
	return s
	

def get_hash(string):
	"""Helper function to get preceding integer
	eg com.openbet == 1003189494
	>>> import binascii
	>>> abs(binascii.crc32('shutit.tk'))
	782914092
	
	Recommended means of determining run order integer part.
	"""
	return abs(binascii.crc32(string))

def create_skeleton(shutit):
	"""Helper function to create a standard module directory ready to run
	and tinker with.
	"""
	shutit_dir = sys.path[0]

	skel_path        = shutit.cfg['skeleton']['path']
	skel_module_name = shutit.cfg['skeleton']['module_name']
	skel_domain      = shutit.cfg['skeleton']['domain']
	skel_domain_hash = shutit.cfg['skeleton']['domainhash']
	skel_script      = shutit.cfg['skeleton']['script']
	skel_example     = shutit.cfg['skeleton']['example']

	if len(skel_path) == 0 or skel_path[0] != '/':
		shutit.fail('Must supply a directory and it must be absolute')
	if os.path.exists(skel_path):
		shutit.fail(skel_path + ' already exists')
	if len(skel_module_name) == 0:
		shutit.fail('Must supply a name for your module, eg mymodulename')
	if not re.match('^[a-zA-z_][0-9a-zA-Z_]+$',skel_module_name):
		shutit.fail('Module names must comply with python classname standards: cf: http://stackoverflow.com/questions/10120295/valid-characters-in-a-python-class-name')
	if len(skel_domain) == 0:
		shutit.fail('Must supply a domain for your module, eg com.yourname.madeupdomainsuffix')

	os.makedirs(skel_path)
	os.mkdir(os.path.join(skel_path, 'configs'))

	templatemodule_path = os.path.join(skel_path, skel_module_name + '.py')
	readme_path = os.path.join(skel_path, 'README.md')
	buildsh_path = os.path.join(skel_path, 'build.sh')
	testsh_path = os.path.join(skel_path, 'test.sh')
	runsh_path = os.path.join(skel_path, 'run.sh')
	buildpushsh_path = os.path.join(skel_path, 'build_and_push.sh')
	buildcnf_path = os.path.join(skel_path, 'configs', 'build.cnf')
	pushcnf_path = os.path.join(skel_path, 'configs', 'push.cnf')

	if skel_example:
		templatemodule = open(os.path.join(shutit_dir, 'docs', 'shutit_module_template.py')).read()
	else:
		templatemodule = open(os.path.join(shutit_dir, 'docs', 'shutit_module_template_bare.py')).read()
	templatemodule = (templatemodule
		).replace('template', skel_module_name
		).replace('GLOBALLY_UNIQUE_STRING', '\'%s.%s.%s\'' % (skel_domain, skel_module_name, skel_module_name)
		).replace('FLOAT',skel_domain_hash + '.00'
	)
	readme = skel_module_name + ': description of module directory in here'
	buildsh = textwrap.dedent('''\
		if [[ x$2 != 'x' ]]
		then
			echo "build.sh takes exactly one argument at most"
			exit 1
		fi
		[[ -z "$SHUTIT" ]] && SHUTIT="$1/shutit"
		[[ ! -a "$SHUTIT" ]] || [[ -z "$SHUTIT" ]] && SHUTIT="$(which shutit)"
		[[ ! -a "$SHUTIT" ]] || [[ -z "$SHUTIT" ]] && SHUTIT="../../shutit"
		# Fall back to trying directory of shutit when module was first created
		[[ ! -a "$SHUTIT" ]] && SHUTIT="''' + shutit_dir + '''/shutit"
		if [[ ! -a "$SHUTIT" ]]
		then
			echo "Must supply path to ShutIt dir or have shutit on path"
			exit 1
		fi
		# This file tests your build, leaving the container intact when done.
		set -e
		$SHUTIT build
		# Display config
		#$SHUTIT sc
		# Debug
		#$SHUTIT build --debug
		# Honour pause points
		#$SHUTIT build --interactive 1
		# Interactive build
		#$SHUTIT build --interactive 2
		# Tutorial
		#$SHUTIT build --interactive 3
		''')
	testsh = textwrap.dedent('''\
		#!/bin/bash
		# Test the building of this module
		set -e
		if [ $0 != test.sh ] && [ $0 != ./test.sh ]
		then
			echo
			echo "Called as: $0"
			echo "Must be run from module root dir like:"
			echo
			echo "  test.sh <path_to_shutit_dir>"
			echo
			echo "or"
			echo
			echo "  ./test.sh <path_to_shutit_dir>"
			exit
		fi
		./build.sh $1
		''')
	runsh = textwrap.dedent('''\
		# Example for running
		docker run -t -i ''' + skel_module_name + ''' /bin/bash
		''')
	buildpushsh = textwrap.dedent('''\
		set -e
		export SHUTIT_OPTIONS="$SHUTIT_OPTIONS --config configs/push.cnf"
		./build.sh $1
		''')
	buildcnf = textwrap.dedent('''\
		# When this module is the one being built, which modules should be built along with it by default?
		# This feeds into automated testing of each module.
		[''' + '%s.%s.%s' % (skel_domain, skel_module_name, skel_module_name) + ''']
		build:yes

		# Aspects of build process
		[build]
		# Allowed images, eg ["ubuntu:12.04"].
		# "any" is a special value meaning any image is ok, and is the default.
		# It's recommended this is locked down as far as possible.
		allowed_images:["any"]
		[repository]
		name:''' + skel_module_name + '''
		''')
	pushcnf = textwrap.dedent('''\
		[repository]
		user:YOUR_USERNAME
		# Fill these out in server- and username-specific config (also in this directory)
		password:YOUR_REGISTRY_PASSWORD_OR_BLANK
		# Fill these out in server- and username-specific config (also in this directory)
		email:YOUR_REGISTRY_EMAIL_OR_BLANK
		tag:no
		push:no
		save:no
		export:no
		#server:REMOVE_ME_FOR_DOCKER_INDEX
		name:''' + skel_module_name + '''
		suffix_date:yes
		suffix_format:%s

		[container]
		rm:false
		''')

	open(templatemodule_path, 'w').write(templatemodule)
	open(readme_path, 'w').write(readme)
	open(buildsh_path, 'w').write(buildsh)
	os.chmod(buildsh_path, os.stat(buildsh_path).st_mode | 0111) # chmod +x
	open(testsh_path, 'w').write(testsh)
	os.chmod(testsh_path, os.stat(testsh_path).st_mode | 0111) # chmod +x
	open(runsh_path, 'w').write(runsh)
	os.chmod(runsh_path, os.stat(runsh_path).st_mode | 0111) # chmod +x
	open(buildpushsh_path, 'w').write(buildpushsh)
	os.chmod(buildpushsh_path, os.stat(buildpushsh_path).st_mode | 0111) # chmod +x
	# build.cnf should be read-only (maintainer changes only)
	open(buildcnf_path, 'w').write(buildcnf)
	os.chmod(buildcnf_path, 0400)
	open(pushcnf_path, 'w').write(pushcnf)
	os.chmod(pushcnf_path, 0600)

	if skel_script is not None:
		print textwrap.dedent('''\
			================================================================================
			Please note that your bash script in:
			''' + skel_script + '''
			should be a simple set of one-liners
			that return to the prompt. Anything fancy with ifs, backslashes or other
			multi-line commands need to be handled more carefully.
			================================================================================''')

		# egrep removes leading space
		# grep removes comments
		# sed1 ensures no confusion with double quotes
		# sed2 replaces script lines with shutit code
		# sed3 uses treble quotes for simpler escaping of strings
		sbsi = '/tmp/shutit_bash_script_include_' + str(int(time.time()))
		skel_mod_path = os.path.join(skel_path, skel_module_name + '.py')
		# TODO: we probably don't need all these external programs any more
		calls = [
				#egrep -v '^[\s]*$' myscript.sh | grep -v '^#' | sed "s/"$/" /;s/^/              shutit.send("""/;s/$/""")/" > /tmp/shutit_bash_script_include_1400206744
			r'''egrep -v '^[\s]*$' ''' + skel_script + r''' | grep -v '^#' | sed "s/\"$/\" /;s/^/\t\tshutit.send(\"\"\"/;s/$/\"\"\")/" > ''' + sbsi,
			r'''sed "41r ''' + sbsi + '" ' + skel_mod_path + ' > ' + skel_mod_path + '.new''',
			r'''mv ''' + skel_mod_path + '''.new ''' + skel_mod_path
		]
		for call in calls:
			subprocess.check_call(['bash', '-c', call])

	# Are we creating a new folder inside an existing git repo?
	if subprocess.call(['git', 'status'], stdout=open(os.devnull, 'wb')) != 0:
		subprocess.check_call(['git', 'init'], cwd=skel_path)
		subprocess.check_call([
			'cp', os.path.join(shutit_dir, '.gitignore'), '.gitignore'
		], cwd=skel_path)

	print textwrap.dedent('''\
	================================================================================
	Run:

	    cd ''' + skel_path + '; ' + shutit_dir + '''/shutit build --interactive 3

	And follow the instructions in the output.

	An image called ''' + skel_module_name + ''' will be created and can be run
	with the run.sh command.
	================================================================================''')

