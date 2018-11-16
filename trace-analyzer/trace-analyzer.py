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


def check_requirements():
    """
    Checks if all necessary programs are installed.

    :return: True if all tools are available, False otherwise
    """
    for tool in ["capinfos", "tshark"]:
        if not find_executable(tool):
            return False
    return True


def run_command(command, quiet):
    """
    Run given command and provide its output as a result.

    :param command: command to be run
    :param quiet: set to true to not print any information output
    :return: command output or None if error occurred
    """
    if not quiet:
        print("[info] Running command: " + command)
    command_process = subprocess.Popen(shlex.split(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = command_process.communicate()

    if stderr:
        print("[error] Command \"{command}\" returned an error:\n{error}".format(command=command, error=stderr))
        return None
    else:
        return stdout


def process_tshark_conversations(tshark_output):
    """
    Process output from the tshark conversations command and return parsed array of dictionaries.

    :param tshark_output: output obtained by running tshark command
    :return: array of dictionaries with parsed tshark conversations
    """
    # Remove white spaces, split lines, and remove header plus bottom lines
    output_lines = tshark_output.decode('utf-8').strip().split('\n')
    output_lines = output_lines[5:-1]

    tshark_result = []
    for line in output_lines:
        fields = re.split("[: ]+", line)
        conversation = {
            "IP A": fields[0],
            "Port A": int(fields[1]),
            "IP B": fields[3],
            "Port B": int(fields[4]),
            "Frames B-A": int(fields[5]),
            "Bytes B-A": int(fields[6]),
            "Frames A-B": int(fields[7]),
            "Bytes A-B": int(fields[8]),
            "Frames": int(fields[9]),
            "Bytes": int(fields[10]),
            "Relative start": float(fields[11].replace(',', '.'))
        }
        tshark_result.append(conversation)
    return tshark_result


def get_tcp_conversations(filename, quiet):
    """
    Compute TCP conversations info and return result as dictionary.

    :param filename: capture file to compute TCP conversations on
    :param quiet: set to true to not print any information output
    :return: TCP conversations stats as array of dictionaries or empty array if error occurred
    """
    command = "tshark -r {filename} -q -z conv,tcp".format(filename=filename)
    command_output = run_command(command, quiet)

    if command_output:
        return process_tshark_conversations(command_output)
    else:
        return []


def process_capture_file_properties(capinfos_output):
    """
    Process output from the capinfos command and return parsed properties as dictionary.

    :param capinfos_output: output obtained by running capinfos command
    :return: dictionary with parsed properties
    """
    # Remove white spaces and split lines
    output_lines = capinfos_output.decode('utf-8').strip().split('\n')

    capinfos_result = {}
    for line in output_lines:
        fields = re.split(":\s+", line, 1)
        capinfos_result[fields[0]] = fields[1]
    return capinfos_result


def get_capture_file_properties(filename, quiet):
    """
    Provide information about the capture file.

    :param filename: capture file to analyse
    :param quiet: set to true to not print any information output
    :return: dictionary object with file properties or or empty dictionary if error occurred
    """
    command = "capinfos -S -M {filename}".format(filename=filename)
    command_output = run_command(command, quiet)

    if command_output:
        return process_capture_file_properties(command_output)
    else:
        return {}


def process_mac_ip_pairs(tshark_output):
    """
    Process output from the tshark command with MAC-IP pairs and return parsed array of dictionaries.

    :param tshark_output: output obtained by running tshark command
    :return: array of dictionaries with parsed MAC-IP pairs
    """
    # Remove white spaces, split lines, and get only unique lines
    output_lines = tshark_output.decode('utf-8').strip().split('\n')
    output_lines_unique = set(output_lines)

    tshark_result = []
    for line in output_lines_unique:
        fields = re.split("\s+", line)
        pair = {
            "MAC": fields[0],
            "IP": fields[1]
        }
        tshark_result.append(pair)
    return tshark_result


def get_mac_ip_pairs(filename, quiet):
    """
    Compute mapping of MAC-IP addresses.

    :param filename: capture file to analyse
    :param quiet: set to true to not print any information output
    :return: MAC-IP mapping as array of dictionaries or empty array if error occurred
    """
    command_src = "tshark -nr {filename} -T fields -e eth.src -e ip.src -E separator=/t".format(filename=filename)
    command_dst = "tshark -nr {filename} -T fields -e eth.dst -e ip.dst -E separator=/t".format(filename=filename)
    command_src_output = run_command(command_src, quiet)
    command_dst_output = run_command(command_dst, quiet)

    pairs_result = []
    if command_src_output:
        pairs_result += process_mac_ip_pairs(command_src_output)
    if command_dst_output:
        pairs_result += process_mac_ip_pairs(command_dst_output)
    return pairs_result


if __name__ == "__main__":
    # Argument parser automatically creates -h argument
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--filename", help="Capture filename to calculate statistics on.",
                        type=str, required=True)
    parser.add_argument("-t", "--tcp_conversations", help="Show TCP conversations.",
                        action='store_true', required=False)
    parser.add_argument("-p", "--pairs_mac_ip", help="Show mapping of IP to MAC addresses.",
                        action='store_true', required=False)
    parser.add_argument("-c", "--capture_info", help="Show capture file properties.",
                        action='store_true', required=False)
    parser.add_argument("-q", "--quiet", help="Do not print any information",
                        action='store_true', required=False)
    args = parser.parse_args()

    if not check_requirements():
        print("[error] Script requirements not satisfied. Please install \"tshark\" and \"capinfos\" tools!")
        sys.exit(1)

    if args.tcp_conversations:
        tcp_conversations = get_tcp_conversations(args.filename, args.quiet)
        print(json.dumps(tcp_conversations))

    if args.pairs_mac_ip:
        mac_ip_pairs = get_mac_ip_pairs(args.filename, args.quiet)
        print(json.dumps(mac_ip_pairs))

    if args.capture_info:
        capture_info = get_capture_file_properties(args.filename, args.quiet)
        print(json.dumps(capture_info))
