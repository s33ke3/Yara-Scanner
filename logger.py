# This Mod Version by Davide Bovio && Vincenzo Digilio
# Original Project by Moath Maharmeh

__author__ = "Moath Maharmeh | Modded By Davide Bovio && Vincenzo Digilio "
__project_page__ = "https://github.com/s33ke3/Yara-Scanner"

import logging
import settings
import common_functions


logging.basicConfig(handlers=[logging.FileHandler(filename=settings.debug_log_file_path, encoding='utf-8', mode='a+')],
                    level=logging.DEBUG,
                    format="%(asctime)s  %(levelname)-8s %(message)s",
                    datefmt=settings.date_time_format)


def log_error(message, module_name):
    if settings.debug_log_enabled and "ERROR" in settings.debug_log_level:
        logging.error("({}): {}".format(module_name, message))


def log_debug(message, module_name):
    if settings.debug_log_enabled and "DEBUG" in settings.debug_log_level:
        logging.debug("({}): {}".format(module_name, message))


def log_critical(message, module_name):
    if settings.debug_log_enabled and "CRITICAL" in settings.debug_log_level:
        logging.critical("({}): {}".format(module_name, message))


def log_warning(message, module_name):
    if settings.debug_log_enabled and "WARNING" in settings.debug_log_level:
        logging.warning("({}): {}".format(module_name, message))


def log_info(message, module_name):
    if settings.debug_log_enabled and "INFO" in settings.debug_log_level:
        logging.info("({}): {}".format(module_name, message))


def log_incident(file_path, rules_matched, yara_rules_file_name):
    try:
        # Log format: [%time%] "%file_path%" "%rules_matched%" "yara_rules_file_name"
        log_row = "[{}] \"{}\" \"{}\" \"{}\"".format(common_functions.get_datetime(), file_path, rules_matched, yara_rules_file_name)

        with open(settings.log_file_path, 'a+', encoding='utf8') as f:
            f.write(log_row)
            f.write("\n")
    except Exception as e:
        log_critical(e, "logger.py")