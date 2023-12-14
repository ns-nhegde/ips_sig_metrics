import os
import csv
import logging
import datetime

from dateutil.relativedelta import relativedelta

from utils.archive import get_security_rules
from ips_sig_parse.sig_parse.parse import Signature

logging.basicConfig(level="DEBUG")
LOGGER = logging.getLogger(__name__)


def read_rule_file(rule_fpath):
    """
    This function reads each rule within the given rule file and parses it.

    :param rule_fpath: Full path to rule file
    :type rule_fpath: str
    :return: List of Signature objects
    :rdict: list of <class 'ips_sig_parse.sig_parse.parse.Signature'>
    """
    LOGGER.debug(f"Reading rule file: {rule_fpath}")
    sigs = []

    with open(rule_fpath, "r") as f:
        for ff in f.readlines():
            sigs.append(Signature(ff.strip()))

    return sigs


def read_sid_file(metadata_fpath):
    sids = []

    with open(metadata_fpath, "r") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            sids.append(int(row[0]))

    return sids


def list_sigs(archive_fpath):
    """
    This function builds a list of security-category signatures in the given
    content build archive.

    :param archive_fpath: Full path to .deb build archive
    :type archive_fpath: str
    :return: List of security-category signatures
    :rtype: list of str
    """
    sigs = []

    # Get all security-category rules
    security_rules = get_security_rules(archive_fpath)

    for rule_file in security_rules:
        sigs.extend(read_rule_file(rule_file))

    return sigs


def build_sid_timestamp_mapping(metadata_fpath):
    """
    Builds a mapping of SID -> creation timestamp from the given metadata file.
    The following assumptions are made about the metadata file:
        1. File is of CSV format
        2. Column 1 is SID and column 2 is creation timestamp

    :param metadata_fpath: Path to file containing sig metadata
    :type metadata_fpath: str
    :return: Mapping of SID -> creation timestamp
    :rtype: dict
    """
    LOGGER.debug(f"Building a mapping of SID->creation timestamp "
                 f"from {metadata_fpath}")
    mapping = {}

    if not os.path.isfile(metadata_fpath):
        LOGGER.error(f"{metadata_fpath} does not exist.")
        return mapping

    with open(metadata_fpath, "r") as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            sid, creation_timestamp, _ = row
            mapping[int(sid)] = creation_timestamp

    return mapping


def calc_sig_age(sig_obj, time_today_utc, sid_time_mapping):
    """
    This function calculates the age of the given signature and updates the
    associated Signature object

    :param sig_obj: Signature object
    :type sig_obj: <class 'ips_sig_parse.sig_parse.parse.Signature'>
    :param time_today_utc: Time today UTC
    :type time_today_utc: <class 'datetime.datetime'>
    :param sid_time_mapping: SID->creation timestamp mapping
    :type sid_time_mapping: dict
    :return: Updated signature object
    :rtype: <class 'ips_sig_parse.sig_parse.parse.Signature'>
    """
    LOGGER.debug(f"Calculating age of signature ID: {sig_obj.signature_id}")
    creation_timestamp = sid_time_mapping.get(sig_obj.signature_id, "")
    if creation_timestamp:
        sig_obj.creation_timestamp = creation_timestamp
        creation_timestamp_obj = datetime.datetime.strptime(
            creation_timestamp,
            "%Y-%m-%d %H:%M:%S"
        )
        relative_time = relativedelta(time_today_utc,
                                      creation_timestamp_obj)
        sig_obj.signature_age = float(
            "{:.2f}".format(relative_time.years + relative_time.months / 12 + relative_time.days / 365.25)
        )
    else:
        sig_obj.creation_timestamp = ""
        sig_obj.signature_age = ""

    return sig_obj


def determine_sigs_age(build_archive, metadata_fpath):
    """
    This function determines the age of security-category signatures in the
    given build archive with reference to the signature creation timestamps
    info in the given signature metadata file.

    :param build_archive: Path to .deb content build archive
    :type build_archive: str
    :param metadata_fpath: Path to file containing sig metadata such as creation
                           timestamps
    :type metadata_fpath: str
    :return: List of updated Signature objects
    :rtype: list of <class 'ips_sig_parse.sig_parse.parse.Signature'>
    """
    # Get today timestamp (UTC)
    time_today_utc = datetime.datetime.utcnow()

    # Get list of security rule files contained within the archive
    security_rules = get_security_rules(build_archive)

    # Build mapping of SID -> creation timestamp from metadata file
    sid_time_mapping = build_sid_timestamp_mapping(metadata_fpath)

    # Read rules, build Signature objects and update their creation
    # timestamp and age
    sig_objs = []
    for rule_fpath in security_rules:
        sigs = read_rule_file(rule_fpath)
        for sig in sigs:
            obj = calc_sig_age(sig, time_today_utc, sid_time_mapping)
            sig_objs.append(obj)

    LOGGER.debug(f"Number of signatures: {len(sig_objs)}")
    return sig_objs


def read_cvss_scores(cve_fpath):
    """
    This function builds a mapping of SID -> CVSS scores

    :param cve_fpath: Full path to file containing CVE metadata such as CVSS
                      scores
    :type cve_fpath: str
    :return: Mapping of SID -> CVSS score
    :rtype: dict
    """
    mapping = {}

    with open(cve_fpath, "r") as f:
        reader = csv.reader(f, delimiter="\t")
        # Skip headers
        next(reader, None)
        for row in reader:
            sid, cvss = row
            if sid in mapping:
                raise Exception(f"Duplicate SID: {sid} in {cve_fpath} contents")
            mapping[int(sid)] = cvss

    return mapping


def determine_cvss_scores(build_archive, metadata_fpath):
    """
    This function determines the CVSS scores for all security-category
    signatures in the given build archive with reference to the CVE info
    in the given metadata file

    :param build_archive: Path to .deb content build archive
    :type build_archive: str
    :param metadata_fpath: Path to file containing CVE metadata such as CVSS
                           scores
    :type metadata_fpath: str
    :return: List of updated signature objects
    :rtype: list of <class 'ips_sig_parse.sig_parse.parse.Signature'>
    """
    sig_objs = []

    # Get list of security rule files contained within the archive
    security_rules = get_security_rules(build_archive)

    # Read file containing CVE metadata per SID
    sid_cvss = read_cvss_scores(metadata_fpath)

    for rule_fpath in security_rules:
        objs = read_rule_file(rule_fpath)
        for sig in sig_objs:
            sig.cvss = sid_cvss.get(sig.signature_id, "")
        sig_objs.extend(objs)

    return sig_objs


def read_poc_links(poc_fpath):
    """
    This function builds a mapping of SID -> POC links

    :param poc_fpath: Full path to file containing POC metadata such as POC
                      links
    :type poc_fpath: str
    :return: Mapping of SID -> POC links
    :rtype: dict
    """
    mapping = {}

    with open(poc_fpath, "r") as f:
        reader = csv.reader(f, delimiter="\t")
        # Skip headers
        next(reader, None)
        for row in reader:
            sid, links = row
            if sid in mapping:
                raise Exception(f"Duplicate SID: {sid} in {poc_fpath} contents")
            mapping[int(sid)] = links

    return mapping


def determine_pocs_links(build_archive, metadata_fpath):
    """
    This function determines the POC links for all security-category
    signatures in the given build archive with reference to the POC info
    in the given metadata file

    :param build_archive: Path to .deb content build archive
    :type build_archive: str
    :param metadata_fpath: Path to file containing POC metadata such as POC links
    :type metadata_fpath: str
    :return: List of updated signature objects
    :rtype: list of <class 'ips_sig_parse.sig_parse.parse.Signature'>
    """
    sig_objs = []

    # Get list of security rule files contained within the archive
    security_rules = get_security_rules(build_archive)

    # Read file containing POC metadata per SID
    sid_pocs = read_poc_links(metadata_fpath)

    for rule_fpath in security_rules:
        objs = read_rule_file(rule_fpath)
        for sig in sig_objs:
            sig.pocs = sid_pocs.get(sig.signature_id, "")
        sig_objs.extend(objs)

    return sig_objs
