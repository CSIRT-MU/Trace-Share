#!/usr/bin/env python

#
# BSD 3-Clause License
#
# Copyright (c) 2018, CSIRT-MU, Masaryk University
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

"""
Script to run commands on attacker machine within the TraceCreator and capture packet trace and scripts output
based on given configuration.

Needs elevated privileges due to tshark ability to store files in a shared folder.

Requirements:
    * tshark
    * Python 3
    * Python modules: termcolor, paramiko, YAML

Usage:
    # ./trace-creator.py -c <configuration_file> -o <output_directory> -i <capture_interface>
        -d <additional_capture_delay> -u <ssh_username> -p <ssh_password>
"""

# Common python modules
import sys  # Common system functions
import os  # Common operating system functions
import argparse  # Arguments parser
import subprocess  # Executes commands in shell
import time  # Manipulates time values
import re  # Regular expressions support
import shlex  # Split the string s using shell-like syntax
import shutil  # Copy files and directory trees

# Additional python modules
from termcolor import cprint  # Colors in the console output
import paramiko  # SSH connection module
import yaml  # YAML configuration parser


def create_capture_directory(directory):
    """
    Creates temporary capture directory (script requires other directory than virtually shared).

    :param directory: capture directory path
    """
    if not os.path.exists(directory):
        os.makedirs(directory)
    subprocess.call("chmod 777 " + directory, shell=True)


def get_task_id(task, timestamp):
    """
    Generates task ID with format "<timestamp>-<task_name>".

    :param task: parsed configuration of one task from the whole configuration file
    :param timestamp: timestamp of the task
    :return: normalized file name
    """
    task_id = "{timestamp}-{name}".format(timestamp=timestamp, name=task["name"][:50].lower())
    # Remove invalid characters from the tak name
    return re.sub(r'[ @#$%^&*<>{}:|;\'\\\"/]', r'_', task_id)


def host_configure(host, command, timestamp, output_directory, username, password):
    """
    Run given command on the host via SSH connection.

    :param host: IP address of the remote host
    :param command: command to run
    :param timestamp: timestamp of the task
    :param output_directory: directory path to store commands output
    :param username: SSH connection username
    :param password: SSH connection password
    """
    cprint("[info] Configuration of host: " + host, "green")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(host, username=username, password=password)

    stdin_handle, stdout_handle, stderr_handle = ssh_client.exec_command(command)
    stdout = stdout_handle.read()
    stderr = stderr_handle.read()

    if stdout or stderr:
        directory_name = "{path}/{task_id}/".format(path=output_directory, task_id=get_task_id(task, timestamp))
        if not os.path.exists(directory_name):
            os.makedirs(directory_name)

        if stdout:
            with open(directory_name + host + ".out", 'w') as out_file:
                out_file.write(stdout)
            cprint("[info] Command output: \n" + str(stdout), "green")

        if stderr:
            with open(directory_name + host + ".err", 'w') as err_file:
                err_file.write(stdout)
            cprint("[warning] Command error output: \n" + str(stderr), "blue")

    ssh_client.close()


def start_tshark(task, network_interface, capture_directory, timestamp):
    """
    Starts tshark capture process based on task configuration.

    :param task: parsed configuration of one task from the whole configuration file
    :param network_interface: capture network interface
    :param capture_directory: temporary directory to store generated data
    :param timestamp: timestamp of the task
    :return: initialized tshark process
    """
    cprint("[info] Starting tshark capture...", "green")
    capture_file_path = "{path}/{filename}.pcapng".format(path=capture_directory,
                                                          filename=get_task_id(task, timestamp))

    tshark_command = "tshark -i {interface} -q -w {output_file} -F pcapng".format(interface=network_interface,
                                                                                  output_file=capture_file_path)
    if "filter" in task:
        tshark_command += " -f \"{filter}\"".format(filter=task["filter"])
				
    # shlex.split splits into shell args list, alternatively use without shlex.split and add shell=True
    tshark_process = subprocess.Popen(shlex.split(tshark_command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return tshark_process


def run_command(task, timestamp, output_directory):
    """
    Run task command and provide its output.

    :param task: parsed configuration of one task from the whole configuration file
    :param timestamp: timestamp of the task
    :param output_directory: directory for log and error files
    """
    cprint("[info] Running command: " + task["command"], "green")

    process = subprocess.Popen(shlex.split(task["command"]), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if stdout:
        log_filename = "{path}/{filename}.out".format(path=output_directory, filename=get_task_id(task, timestamp))
        with open(log_filename, 'w') as out_file:
            out_file.write(stdout)
        cprint("[info] Command output: \n" + str(stdout), "green")

    if stderr:
        err_filename = "{path}/{filename}.err".format(path=output_directory, filename=get_task_id(task, timestamp))
        with open(err_filename, 'w') as err_file:
            err_file.write(stderr)
        cprint("[warning] Command error output: \n" + str(stderr), "blue")


def move_files(source_directory, destination_directory):
    """
    Move all files within the source_directory to the destination_directory.

    :param source_directory: source directory with files
    :param destination_directory: destination directory
    """
    for item in os.listdir(source_directory):
        source = os.path.join(source_directory, item)
        destination = os.path.join(destination_directory, item)
        shutil.move(source, destination)


def process_creator_task(task, capture_directory, args):
    """
    Process task in given configuration. Prepare hosts, start tshark capture with specified filter, run desired
    command, and provide command outputs together with generated capture files.

    :param task: parsed configuration of one task from the whole configuration file
    :param capture_directory: temporary directory to store generated data
    :param args: creator script arguments
    """
    cprint("[info] Processing task: " + task["name"], "green")
    task_timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")

    if "configuration" in task:
        for host_configuration in task["configuration"]:
            host_configure(host_configuration["ip"], host_configuration["command"], task_timestamp,
                           args.output_directory, args.username, args.password)

    tshark_process = start_tshark(task, args.interface, capture_directory, task_timestamp)
    run_command(task, task_timestamp, args.output_directory)
    time.sleep(args.delay)
		
    tshark_process.terminate()
    move_files(capture_directory, args.output_directory)
    cprint("[info] Finished task: " + task["name"], "green")


if __name__ == "__main__":
    # Argument parser automatically creates -h argument
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--configuration", help="Path to the configuration file.", type=argparse.FileType('r'),
                        required=False, default="/vagrant/configuration/trace-creator.yml")
    parser.add_argument("-o", "--output_directory", help="Output directory for captured files.", type=str,
                        required=False, default="/vagrant/capture/")
    parser.add_argument("-i", "--interface", help="Capture network interface.", type=str,
                        required=False, default="enp0s8")
    parser.add_argument("-d", "--delay", help="Delay to stop capture after process finished (in seconds).", type=int,
                        required=False, default=3)
    parser.add_argument("-u", "--username", help="Username for connection to remote host via SSH.", type=str,
                        required=False, default="vagrant")
    parser.add_argument("-p", "--password", help="Username for connection to remote host via SSH.", type=str,
                        required=False, default="vagrant")
    args = parser.parse_args()

    try:
        configuration = yaml.load(args.configuration)
    except yaml.YAMLError as exc:
        cprint("[error] YAML configuration not correctly loaded: " + str(exc), "red")
        sys.exit(1)

    # Create temporary capture directory (necessary for tshark)
    capture_directory = "/tmp/capture/"
    create_capture_directory(capture_directory)

    # Create output directory if not exists
    if not os.path.exists(args.output_directory):
        os.makedirs(args.output_directory)

    cprint("[info] Starting commands execution and packet capture...", "green")
    for task in configuration:
        process_creator_task(task, capture_directory, args)

    cprint("[info] All data exported!", "green")
    cprint("[info] Now you can destroy TraceCreator environment using \"vagrant destroy\" command.", "green")
