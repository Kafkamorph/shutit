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


from shutit_module import ShutItModule
import util

class ssh_server(ShutItModule):

	def check_ready(self,config_dict):
		return True

	def is_installed(self,config_dict):
		return False

	def build(self,config_dict):
		container_child = util.get_pexpect_child('container_child')
		util.install(container_child,config_dict,'openssh-server',config_dict['expect_prompts']['root_prompt'])
		util.send_and_expect(container_child,'mkdir -p /var/run/sshd',config_dict['expect_prompts']['root_prompt'])
		util.send_and_expect(container_child,'chmod 700 /var/run/sshd',config_dict['expect_prompts']['root_prompt'])
		# Set up root bashrcs once
		# Root bash files seem to be inconsistent, so this the canonical one...
		util.add_line_to_file(container_child,'export HOME=/root','/root/.bashrc',config_dict['expect_prompts']['root_prompt'])
		# ... and the others point to it.
		util.add_line_to_file(container_child,'. /root/.bashrc','/root/.bash_profile.sh',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'. /root/.bashrc','/.bashrc',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'. /root/.bashrc','/.bash_profile',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'# sshd','/root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		## To get sshd to work, we need to create a privilege separation directory.
		## see http://docs.docker.io/en/latest/examples/running_ssh_service/
		util.add_line_to_file(container_child,'mkdir -p /var/run/sshd','/root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'chmod 700 /var/run/sshd','/root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'start-stop-daemon --start --quiet --oknodo --pidfile /var/run/sshd.pid --exec /usr/sbin/sshd','/root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.add_line_to_file(container_child,'start-stop-daemon --stop --quiet --oknodo --pidfile /var/run/sshd.pid','/root/stop_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.send_and_expect(container_child,'chmod +x /root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.send_and_expect(container_child,'chmod +x /root/stop_ssh.sh',config_dict['expect_prompts']['root_prompt'])
		util.send_and_expect(container_child,'passwd','Enter new',check_exit=False)
		util.send_and_expect(container_child,config_dict['container']['password'],'Retype new',check_exit=False)
		util.send_and_expect(container_child,config_dict['container']['password'],config_dict['expect_prompts']['root_prompt'])
		return True

	def start(self,config_dict):
		container_child = util.get_pexpect_child('container_child')
		util.send_and_expect(container_child,'/root/start_ssh.sh',config_dict['expect_prompts']['root_prompt'],check_exit=False)
		return True

	def stop(self,config_dict):
		container_child = util.get_pexpect_child('container_child')
		util.send_and_expect(container_child,'/root/stop_ssh.sh',config_dict['expect_prompts']['root_prompt'],check_exit=False)
		return True

	def cleanup(self,config_dict):
		return True

	def finalize(self,config_dict):
		return True

	def test(self,config_dict):
		return True

	def get_config(self,config_dict):
		return True


if not util.module_exists('com.ian.miell.ssh_server.ssh_server'):
	obj = ssh_server('com.ian.miell.ssh_server.ssh_server',0.321)
	obj.add_dependency('com.ian.miell.setup')
	util.get_shutit_modules().add(obj)
	ShutItModule.register(ssh_server)

