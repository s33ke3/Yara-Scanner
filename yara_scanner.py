__author__ = "Moath Maharmeh | Modded By CyberDivision "
__project_page__ = "https://github.com/iomoath/yara-scanner"

import logger
import common_functions
import yara_match
import os
import settings
import access_log_parser

module_name = os.path.basename(__file__)

def get_file_path_list(root_dir, recursive, filters):
    if recursive:
        return common_functions.recursive_file_scan(root_dir, files_only=True, filters=filters)
    else:
        return common_functions.get_file_set_in_dir(root_dir, files_only=True, filters=filters)


def scan_file(file_path):
    file_path = u"{}".format(file_path)

    if file_path is None or not os.path.isfile(file_path):
        msg = "The provided path '{}' is invalid.".format(file_path)
        logger.log_error(msg, module_name)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_yara_rules_src_dir()
    try:
        logger.log_info('Single file scan started', module_name)
        print('[+] Single file scan started')

        logger.log_debug('Getting Yara-Rules', module_name)
        common_functions.print_verbose('[+] Getting Yara-Rules..')
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, '*.yar')

        match_list = yara_match.match([file_path], yara_rule_path_list)
        print('[+] File scan complete.')
        logger.log_info('File scan complete', module_name)
        return match_list

    except Exception as e:
        common_functions.print_verbose('[-] ERROR: {}'.format(e))
        logger.log_error(e, module_name)
        raise


def scan_directory(directory_path, recursive = False):

    directory_path = u"{}".format(directory_path)

    if directory_path is None or not os.path.isdir(directory_path):
        msg = "The provided path '{}' is invalid.".format(directory_path)
        logger.log_error(msg, module_name)
        print('[-] ERROR: {}'.format(msg))
        raise Exception(msg)

    # Check if there are any rules in yara-rules-src dir and compile them
    common_functions.compile_yara_rules_src_dir()

    try:
        logger.log_info('Directory scan started', module_name)
        print('[+] Directory scan started')

        logger.log_debug('Getting files path(s) for scan', module_name)
        common_functions.print_verbose('[+] Getting files path(s) for scan..')
        file_path_list = get_file_path_list(directory_path, recursive, '*')

        logger.log_debug('[+] {} File to process'.format(len(file_path_list)), module_name)
        print('[+] {} File to process.'.format(len(file_path_list)))

        logger.log_debug('Getting Yara-Rules', module_name)
        common_functions.print_verbose('[+] Getting Yara-Rules..')
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, '*.yar')

        match_list = yara_match.match(file_path_list, yara_rule_path_list)

        print('[+] Directory scan complete.')
        logger.log_info('Directory scan complete', module_name)

        return match_list

    except Exception as e:
        common_functions.print_verbose('[-] ERROR: {}'.format(e))
        logger.log_error(e, module_name)
        raise


def combine_file_path_list_with_dir(file_list, dir_path):

    file_path_set = set()
    for file_path in file_list:
        if file_path is None:
            continue
        full_path = dir_path + file_path
        if os.path.isfile(full_path):
            file_path_set.add(full_path)

    return file_path_set


def scan_access_logs(access_logs_file_path, www_dir_path, tail=0):
    """
    Attempt to match accessed files access logs with Yara-Rules
    :param access_logs_file_path: path to access log file
    :param www_dir_path: path to public web directory ex; www, public_html
    :param tail: read last n lines from access log. if value is 0 then will read the whole file
    :return: list of dictionaries containing match details for each file. example: {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
    """
    try:
        if access_logs_file_path is None or not os.path.isfile(access_logs_file_path):
            logger.log_error('The provided path "{}" is invalid '.format(access_logs_file_path), module_name)
            print('[-] ERROR: The provided path "{}" is invalid.'.format(access_logs_file_path))
            return None

        # Check if there are any rules in yara-rules-src dir and compile them
        common_functions.compile_yara_rules_src_dir()

        logger.log_info('Access logs scan started', module_name)
        print('[+] Access logs scan started')

        logger.log_debug('Reading access logs file', module_name)
        common_functions.print_verbose('[+] Reading access logs file..')

        if tail > 0:
            lines = common_functions.tail(access_logs_file_path, tail)
        else:
            lines = common_functions.read_file_lines(access_logs_file_path)


        logger.log_debug('Attempting to parse accessed files path(s) from access logs', module_name)
        common_functions.print_verbose('[+] Attempting to parse accessed files path(s) from access logs..')

        # combine file path with www dir path
        file_path_set = combine_file_path_list_with_dir(access_log_parser.get_accessed_files_list(lines), www_dir_path)

        logger.log_debug('[+] {} File to process'.format(len(file_path_set)), module_name)
        print('[+] {} File to process.'.format(len(file_path_set)))

        logger.log_debug('Getting Yara-Rules', module_name)
        common_functions.print_verbose('[+] Getting Yara-Rules..')
        yara_rule_path_list = get_file_path_list(settings.yara_rules_directory, True, '*.yar')
        match_list = yara_match.match(file_path_set, yara_rule_path_list)

        print('[+] Access logs scan complete.')
        logger.log_info('Access logs scan complete', module_name)

        return match_list

    except Exception as e:
        common_functions.print_verbose('[-] ERROR: {}'.format(e))
        logger.log_error(e, module_name)
        return None

