# This Mod Version by Davide Bovio && Vincenzo Digilio
# Original Project by Moath Maharmeh

__author__ = "Moath Maharmeh | Modded By Davide Bovio && Vincenzo Digilio "
__project_page__ = "https://github.com/iomoath/yara-scanner"

from logging import raiseExceptions
import pathlib

import logger
import common_functions
import os
import settings
import time
import yara
import concurrent.futures

module_name = os.path.basename(__file__)

def matchrule(rule_path, file_path):
    
    try:
        logger.log_debug('Loading rules from {}'.format(rule_path), module_name)

        if type(rule_path) is pathlib.PosixPath:
            rule_path = rule_path.absolute().as_posix()

        rules = yara.load(rule_path)

        file_size = os.path.getsize(file_path)

        if file_size > settings.max_file_size:
            message = "Size of {} ({}) exceed {}".format(file_path, file_size, settings.max_file_size)
            logger.log_warning(message, module_name)
            common_functions.print_verbose(message)
            return None

        logger.log_debug('Attempting to match "{}" with  "{}"'.format(file_path, rule_path), module_name)
        common_functions.print_verbose('[+] Attempting to match "{}" with "{}'.format(file_path, os.path.basename(rule_path)))

        # Attempt to match

        # Check if file path contain non-ascii chars, as it's will cause error in Windows env
        is_ascii_path = common_functions.is_ascii(file_path)
        if not is_ascii_path and os.name == 'nt':
            with open(file_path, 'rb') as f:
                matches = rules.match(data=f.read(), timeout=settings.yara_matching_timeout)
        else:
            matches = rules.match(file_path, timeout=settings.yara_matching_timeout)

        if len(matches) > 0:
            record = {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
            
            logger.log_info('Found {} matches in "{}" {} "{}"'.format(len(matches), file_path, matches, rule_path), module_name)
            if settings.verbose_enabled:
                print('[*] Found {} matches: {}'.format(len(matches), matches))
            else:
                print('[*] Found {} matches in "{}" {} :"{}"'.format(len(matches), file_path, matches,
                                                                os.path.basename(rule_path)))
            logger.log_incident(file_path, matches, rule_path)
            common_functions.report_incident_by_email(file_path, matches, rule_path, common_functions.get_datetime())
        
            return record
        
    except yara.Error as e:
        message = '[-] ERROR: {} \n     in  {}  for rule {}'.format(e, file_path, rule_path)
        common_functions.print_verbose(message)        
        logger.log_error(message, module_name)        
        return None

    except Exception as e:                
        message = '[-] ERROR: {} \n     in  {}  for rule {}'.format(e, file_path, rule_path)
        common_functions.print_verbose(message)
        logger.log_error(message, module_name)        
        return None

def matchfile(file_path, yara_rules_path_list, verbose_enabled, debug_log_enabled):

    internal_match_list = []
    settings.verbose_enabled = verbose_enabled
    settings.debug_log_enabled = debug_log_enabled
    
    if type(file_path) is pathlib.PosixPath:
        file_path = file_path.absolute().as_posix()

    # Check if file to analyze is a file
    if not os.path.isfile(file_path):
        common_functions.print_verbose('[-] Skip file: {}'.format(file_path))
        return None

    # Check if file to analyze in exluding list
    if common_functions.should_exclude(file_path):
        common_functions.print_verbose('[-] Excluded file: {}'.format(file_path))
        return None
    
    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as executor:
        fs = [executor.submit(matchrule, r, file_path) for r in yara_rules_path_list]
        for f in concurrent.futures.as_completed(fs):
            try:
                result = f.result()
            except Exception as e:                
                common_functions.print_verbose('[-] ERROR: {}'.format(e))        
                logger.log_error(e, module_name)                
            else:
                if result != None:
                    internal_match_list.append(result)
    
    # Return status Ok
    title = "File processed"
    common_functions.print_verbose('[-] {}: {}'.format(title, file_path))
    return internal_match_list

def match(path_list, yara_rules_path_list):
    """
    Attempt to match file content with yara rules
    :param path_list: list contains path(s) of files to match with yara rules
    :param yara_rules_path_list: yara rule(s) path list
    :return: list of dictionaries containing match details for each file. example: {"file": file_path, "yara_rules_file": rule_path, "match_list": matches}
    """
    # Store matches found
    match_list = []

    start_time = time.time()

    filecount = 0
    totalfiles = len(path_list)

    print("Using {} CPU for processing".format(os.cpu_count()))

    with concurrent.futures.ThreadPoolExecutor(os.cpu_count()) as executor:
        fs = [executor.submit(matchfile, f, yara_rules_path_list, settings.verbose_enabled, settings.debug_log_enabled) for f in path_list]
        for f in concurrent.futures.as_completed(fs):
            try:
                result = f.result()                
            except Exception as e:
                if settings.verbose_enabled == False:
                    print("File {} of {} - Error detected: {}".format(filecount, totalfiles, e))
            else:                                        
                if result != None:
                    for r in result:
                        match_list.append(r)

                filecount += 1
                if settings.verbose_enabled == False:    
                    print("File {} of {}".format(filecount, totalfiles))
    
    end_time = time.time()    
    print("Total files: {} - {} seconds".format(totalfiles, (end_time - start_time)))

    return match_list