#!/usr/bin/env python3
from lookups.url_lookup import *
from lookups.ip_lookup import *
from lookups.hash_lookup import *
import argparse
import logging
import os
import re

# STATIC

HASHLEE_DESCRIPTION = 'This script will extract and cross reference indicators with OSINT sources'
HASHLEE_VERBOSE = False
HASHLEE_SAVE = False
INDICATOR_LIST = {}
CHECKED_INDICATORS = []

# Initiate Logger
log = logging.getLogger("hashlee-logger")


def main():
    """
    Main functionality of hashlee
    :return: Pass
    """
    # Variables
    input_files = []

    # Retrieve and build script arguments
    parser = argparse.ArgumentParser(description=HASHLEE_DESCRIPTION)
    parser.add_argument("p_input", help="file or directory to run hashlee against")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-d", "--debug", help="output logging",
                        action="store_true")
    parser.add_argument("-s", "--save", help="save output to a file",
                        action="store_true")
    args = parser.parse_args()

    # Set options based on argparse
    if args.debug:
        logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
        log.info(" Starting Hashlee logging!")
        log.info(" Running in DEBUG MODE - You will see all logging in this output")

    if args.verbose:
        log.info(" Running in VERBOSE MODE - You will see all lookups in this output")
        HASHLEE_VERBOSE = True

    if args.save:
        log.info(" Running in SAVE MODE - You will save output to file")
        HASHLEE_SAVE = True

    print("[====== STARTING: HASHLEE ======]")

    # Attempts to determine what the input type provided is
    input_files = determine_input_type(input_files, args.p_input)

    # Checks to see if there are one or moe files and if so will parse files
    if input_files:
        log.info(" Seeing 1 or more files will")
        for f in input_files:
            log.info(" Pulling indicators from file: {}".format(f))
            with open(f) as fp:
                for line in fp:
                    if parse_for_indicators(line):
                        log.info(" Found indicators in {}".format(line))
                    else:
                        log.info(" Unable to find indicators in file: {}".format(line))
    else:
        # if no files just "do it live!"
        log.info(" Looking up {} as a single indicator".format(args.p_input))
        if parse_for_indicators(args.p_input):
            log.info(" {} is an indicator".format(args.p_input))
        else:
            log.error(" This is not an indicator, please try again with valid input")


def inspect_indicator(indicator, indicator_type):
    """
    Run indicator lookups on OSINT
    :param indicator:
    :param indicator_type:
    :return:
    """
    #Variables
    search_result = ''
    if indicator in CHECKED_INDICATORS:
        return False
    else:
        CHECKED_INDICATORS.append(indicator)

    log.info(" Processing {} as a {}".format(indicator, indicator_type))

    if indicator_type == "HASH":
        pass
    elif indicator_type == "URL":
        search_result = url_osint_lookup(indicator, log)
    elif indicator_type == "IP":
        search_result = ip_osint_lookup(indicator, log)
    else:
        log.error(" INVALID INDICATOR TYPE FOUND")

    if search_result:
        # Clean up output
        results_parsed = parse_search_results(search_result)
        log.info(" Updating indicator list for {} with the {}".format(indicator, results_parsed))
        INDICATOR_LIST.update({indicator: results_parsed})
        print("[POSSIBLE THREAT FOUND] {} on {}".format(indicator.replace(".","[.]"), results_parsed))
        return True
    else:
        return False


def determine_input_type(input_files, p_input):
    """
    Checks to see if the input is a file, directory or single indicator
    :param input_files:
    :param p_input:
    :return input_files:
    """
    if os.path.isfile(p_input):
        log.info(" {} is a file".format(p_input))
        input_files.append(os.path.realpath(p_input))
    elif os.path.isdir(p_input):
        log.info(" {} is a directory".format(p_input))
        for i in os.listdir(p_input):
            input_files.append(os.path.join(os.path.realpath(p_input), i))
    else:
        log.info(" {} is  NOT a file or directory, will continue as an indicator".format(p_input))
        return []
    return input_files


def parse_for_indicators(line):
    """
    Parses each file for indicators and adds them to the indicator list
    :param line:
    :return None:
    """
    # Initialize Variables
    indicators_present = False

    # Checking each indicator type
    md5_list = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{32}(?![a-z0-9])', line)
    if md5_list:
        indicators_present = True
        for md5 in md5_list:
            log.info(" (MD5 found!), Inspecting {} via OSINT".format(md5))
            if inspect_indicator(md5, 'HASH'):
                log.info(" RESULTS FOUND: {} [Adding to results]".format(md5))
            else:
                log.info(" Did not inspect {} or it has been inspected previously".format(md5))
    else:
        log.info(" No MD5 found in line: {}".format(line))

    sha1_list = re.findall(r'(?i)(?<![a-z0-9])[a-f0-9]{40}(?![a-z0-9])', line)
    if sha1_list:
        indicators_present = True
        for sha1 in sha1_list:
            log.info(" (SHA1 found!), Inspecting {} via OSINT".format(sha1))
            if inspect_indicator(sha1, 'HASH'):
                log.info(" RESULTS FOUND: {} [Adding to results]".format(md5))
            else:
                log.info(" Did not find results {} or it has been inspected previously".format(sha1))
    else:
        log.info(" No SHA1 found in line: {}".format(line))

    ip_list = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', line)
    if ip_list:
        indicators_present = True
        for ip in ip_list:
            log.info(" (IP found!), Inspecting {} via OSINT".format(ip))
            if inspect_indicator(ip, 'IP'):
                log.info(" RESULTS FOUND: {} [Adding to results]".format(ip))
            else:
                log.info(" Did not inspect {} or it has been inspected previously".format(ip))
    else:
        log.info(" No IP found in line: {}".format(line))

    url_list = re.findall(r'(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', line)
    if url_list:
        indicators_present = True
        log.info(" (URLs found!): {}".format(url_list))
        for url in url_list:
            log.info(" (URL found!), Inspecting {} via OSINT".format(url))
            if inspect_indicator(url, 'URL'):
                log.info(" RESULTS FOUND: {} [Adding to results]".format(url))
            else:
                log.info(" Did not inspect {} or it has been inspected previously".format(url))
    else:
        log.info(" No URL found in line: {}".format(line))

    # Return whether we were able to pull indicators or not
    if indicators_present == True:
        return True
    else:
        return False

def parse_search_results(search_results):
    """
    Takes the raw indicator results and makes them into one result line
    :param search_results:
    :return parsed_results:
    """
    return ", ".join(search_results)


if __name__ == "__main__":
    """
    Main
    """
    main()
