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
Script to provide information about given PCAP file via standard output in JSON format. This information serves
as an input for a trace normalization and annotation.

Currently available information: TCP conversations, caputre file properties, and MAC-IP pairs.

Requirements:
    * tshark
    * capinfos
    * Python 3
    * Python modules: termcolor

Usage:
    $ ./trace-analyzer.py -f <capture_file> -t -p -c
"""

# Common python modules
import sys  # Common system functions
import argparse  # Arguments parser
import subprocess  # Executes commands in shell
import re  # Regular expressions support
import shlex  # Split the string s using shell-like syntax
import json  # JSON processing functions
from distutils.spawn import find_executable  # Check if required tool is available in PATH

# Additional python modules
from termcolor import cprint  # Colors in the console output


def check_requirements():
    """
    Checks if all necessary programs are installed.

    :return: True if all tools are available, False otherwise
    """
    # Iterate through required tools
    for tool in ["capinfos", "tshark"]:
        # Check if tool is available
        if not find_executable(tool):
            # Required tool not found
            return False
    # All required tools are available
    return True


def run_command(command):
    """
    Run given command and provide its output as a result.

    :param command: command to be run
    :return: command output or None if error occurred
    """
    # Show command info
    cprint("[info] Running command: " + command, "green")

    # Execute command
    command_process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Wait to process finish and get process results
    stdout, stderr = command_process.communicate()

    # Check if error occurred
    if stderr:
        # Show error info
        cprint("[error] Command \"{command}\" returned an error: \n".format(command=command), "red")
        # Return nothing
        return None
    else:
        # Return STDOUT
        return stdout


def process_tshark_conversations(tshark_output):
    """
    Process output from the tshark conversations command and return parsed array of dictionaries.

    :param tshark_output: output obtained by running tshark command
    :return: array of dictionaries with parsed tshark conversations
    """
    # Remove white spaces and split lines
    output_lines = tshark_output.strip().split('\n')
    # Remove header and bottom lines
    output_lines = output_lines[5:-1]

    # Array to store result
    tshark_result = []

    # Process each output line
    for line in output_lines:
        # Split line to separate fields
        fields = re.split("[: ]+", line)
        # Specify conversation object
        conversation = {
            "IP A": fields[0],
            "Port A": fields[1],
            "IP B": fields[3],
            "Port B": fields[4],
            "Frames B-A": fields[5],
            "Bytes B-A": fields[6],
            "Frames A-B": fields[7],
            "Bytes A-B": fields[8],
            "Frames": fields[9],
            "Bytes": fields[10],
            "Relative start": fields[11]
        }
        # Append conversation to tshark_result
        tshark_result.append(conversation)

    # Return parsed conversations
    return tshark_result


def get_tcp_conversations(filename):
    """
    Compute TCP conversations info and return result as dictionary.

    :param filename: capture file to compute TCP conversations on
    :return: TCP conversations stats as array of dictionaries or empty array if error occurred
    """
    # Specify analysis command for tshark
    command = "tshark -r {filename} -q -z conv,tcp".format(filename=filename)
    # Run command and get its output
    command_output = run_command(command)

    # Check if command succeed
    if command_output:
        # Process tshark command output
        return process_tshark_conversations(command_output)
    else:
        # Return empty result
        return []


def process_capture_file_properties(capinfos_output):
    """
    Process output from the capinfos command and return parsed properties as dictionary.

    :param capinfos_output: output obtained by running capinfos command
    :return: dictionary with parsed properties
    """
    # Remove white spaces and split lines
    output_lines = capinfos_output.strip().split('\n')

    # Dictionary to store result
    capinfos_result = {}

    # Process each output line
    for line in output_lines:
        # Split line to separate fields
        fields = re.split(":\s+", line, 1)
        # Append field to the capinfo result object
        capinfos_result[fields[0]] = fields[1]

    # Return parsed capture file properties
    return capinfos_result


def get_capture_file_properties(filename):
    """
    Provide information about the capture file.

    :param filename: capture file to analyse
    :return: dictionary object with file properties or or empty dictionary if error occurred
    """
    # Specify analysis command for capinfos
    command = "capinfos -S -M {filename}".format(filename=filename)
    # Run command and get its output
    command_output = run_command(command)

    # Check if command succeed
    if command_output:
        # Process capinfos command output
        return process_capture_file_properties(command_output)
    else:
        # Return empty result
        return {}


def process_mac_ip_pairs(tshark_output):
    """
    Process output from the tshark command with MAC-IP pairs and return parsed array of dictionaries.

    :param tshark_output: output obtained by running tshark command
    :return: array of dictionaries with parsed MAC-IP pairs
    """
    # Remove white spaces and split lines
    output_lines = tshark_output.strip().split('\n')
    # Get only unique output lines
    output_lines_unique = set(output_lines)

    # Array to store result
    tshark_result = []

    # Process each output line
    for line in output_lines_unique:
        # Split line to separate fields
        fields = re.split("\s+", line)
        # Specify pair object
        pair = {
            "MAC": fields[0],
            "IP": fields[1]
        }
        # Append pair to tshark_result
        tshark_result.append(pair)

    # Return parsed MAC-IP pairs
    return tshark_result


def get_mac_ip_pairs(filename):
    """
    Compute mapping of MAC-IP addresses.

    :param filename: capture file to analyse
    :return: MAC-IP mapping as array of dictionaries or empty array if error occurred
    """
    # Specify analysis commands to get source and destination MAC-IP mapping
    command_src = "tshark -nr {filename} -T fields -e eth.src -e ip.src -E separator=/t".format(filename=filename)
    command_dst = "tshark -nr {filename} -T fields -e eth.dst -e ip.dst -E separator=/t".format(filename=filename)

    # Run both commands to get src and dst pairs
    command_src_output = run_command(command_src)
    command_dst_output = run_command(command_dst)

    # Array to store result pairs
    pairs_result = []

    # Process src pairs output
    if command_src_output:
        pairs_result += process_mac_ip_pairs(command_src_output)

    # Process dst pairs output
    if command_dst_output:
        pairs_result += process_mac_ip_pairs(command_dst_output)

    # Return MAC-IP pairs
    return pairs_result


if __name__ == "__main__":
    # Define application arguments (automatically creates -h argument)
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename", help="Capture filename to calculate statistics on.",
                        type=str, required=True)
    parser.add_argument("-t", "--tcp_conversations", help="Show TCP conversations.",
                        action='store_true', required=False)
    parser.add_argument("-p", "--pairs_mac_ip", help="Show mapping of IP to MAC addresses.",
                        action='store_true', required=False)
    parser.add_argument("-c", "--capture_info", help="Show capture file properties.",
                        action='store_true', required=False)
    # Parse arguments
    args = parser.parse_args()

    # Check if all tool requirements are satisfied
    if not check_requirements():
        # Show error message and exit
        cprint("[error] Script requirements not satisfied. Please install \"tshark\" and \"capinfos\" tools!", "red")
        sys.exit(1)

    # Compute TCP conversations if required
    if args.tcp_conversations:
        # Get TCP conversations
        tcp_conversations = get_tcp_conversations(args.filename)
        # Print conversations to the console
        cprint(json.dumps(tcp_conversations), "white")

    # Get MAC-IP pairs mapping if required
    if args.pairs_mac_ip:
        # Get MAC-IP pairs
        mac_ip_pairs = get_mac_ip_pairs(args.filename)
        # Print MCA-IP paris to the console
        cprint(json.dumps(mac_ip_pairs), "white")

    # Get capture file properties if required
    if args.capture_info:
        # Get capture file properties
        capture_info = get_capture_file_properties(args.filename)
        # Print capture file to the console
        cprint(json.dumps(capture_info), "white")
