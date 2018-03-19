# TraceCreator

A framework for an automated creation of full packet traces based on Vagrant and Ansible virtualization platforms.

## [Vagrant](https://www.vagrantup.com/intro/index.html)
Vagrant is a tool for building and managing virtual machine environments 
in a single workflow. With an easy-to-use workflow and focus on automation, 
Vagrant lowers development environment setup time, increases production parity, 
and makes the "works on my machine" excuse a relic of the past.

Vagrant will isolate dependencies and their configuration within a single disposable, 
consistent environment, without sacrificing any of the tools you are used to working with 
(editors, browsers, debuggers, etc.). Once you or someone else creates a single Vagrantfile, 
you just need to vagrant up and everything is installed and configured for you to work.

[Installation](https://www.vagrantup.com/intro/getting-started/install.html)

[Getting Started Official Guide](https://www.vagrantup.com/intro/getting-started/index.html)

VagrantFile is preconfigured for easy setup of virtual machines divided into attacker and victim categories.
These categories are provided for your convenience.
These categories do not change the behavior of the VMs.

### Usage:

* `$ vagrant up [atatcker|victim<X>]` – Creates and configures guest machines according to your Vagrantfile.
It starts up virtual machines, downloading system images if necessary. 
It will provision these VMs, installing software defined using Ansible and/or bash scripts.

* `vagrant provision [atatcker|victim<X>]` – Runs any configured provisioners against the running Vagrant managed machine.
You can just make simple modifications to the provisioning scripts on your machine, run a vagrant provision, 
and check for the desired results.

* `$ vagrant destroy [name|id]` – Stops the running machine Vagrant is managing and destroys all resources 
that were created during the machine creation process. After running this command, 
your computer should be left at a clean state, as if you never created the guest machine 
in the first place.


### VagrantFile VM Options:
* attacker_ip Attacker IP address.
* victim_prefix Victim IP address prefix. Suffix is generated automatically.
* mask Network mask.
* number_of_victims Defines number of victims genereted.
* config.vm.synced_folder <host directory> <VM directory> Shared folder definition.
* attacker_mem_mb 
* attacker_cpu_num
* victim_mem_mb
* victim_cpu_num

To install software and configure VMs use `vm_config/bootstrap_(victim|attacker).sh` bash script or 
`vm_config/playbook_(victim|attacker).yml` Ansible configuration.

# [Ansible](https://www.ansible.com/)

Ansible is software that automates software provisioning, configuration management, 
and application deployment.

You can use Ansible to automate three types of tasks:

* Provisioning: Set up the various servers you need in your infrastructure.
* Configuration management: Change the configuration of an application, OS, or device; 
start and stop services; install or update applications; implement a security policy; 
or perform a wide variety of other configuration tasks.
* Application deployment: Make DevOps easier by automating the deployment of internally 
developed applications to your production systems.


[Installation](http://docs.ansible.com/ansible/latest/intro_installation.html)

[Getting Started Official Guide](http://docs.ansible.com/ansible/latest/intro_getting_started.html)

## Playbooks

Playbooks are Ansible’s configuration, deployment, and orchestration language. 
They can describe a policy you want your remote systems to enforce, or a set of steps 
in a general IT process.

Playbooks are defined using YAML language. Hence, first line of YAML file starts with `---`.

### Options:
* `hosts`
* `become` Set to ‘true’/’yes’ to activate privilege escalation.
* `tasks`
* `apt_repository` Add or remove an APT repositories in Ubuntu and Debian.
* `apt` Manages apt packages (such as for Debian/Ubuntu).
* `name`

For more information please refer to the official [documentation](http://docs.ansible.com/ansible/latest/index.html).
