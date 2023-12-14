import logging
import argparse

from processor.archive import list_sigs, determine_sigs_age, \
    determine_cvss_scores, determine_pocs_links

logging.basicConfig(level="DEBUG")
LOGGER = logging.getLogger(__name__)


def process_archive(options):
    """
    This function is leveraged when the user provides a .deb content build
    archive.

    :param options: Provided execution options:
        fpath: Full path to .deb content build archive
        list_sigs: List security-category signatures in given archive
        fields: Signature fields to dump
        sig_age: Calculate security-category signature age of signatures in
                 given archive
        cvss: Determine CVSS scores for the given security-category signatures
        pocs: Determine POC links for the given security-category signatures
    :type options: dict
    """
    archive_fpath = options.get("fpath", "")
    sig_fields = options["fields"]

    if options.get("list_sigs", None):
        # python .\main.py archive -f .\files\ips-content.ns_23.147.10_amd64.deb
        # --list --fields signature_id signature_code
        LOGGER.debug(f"Listing signatures in {archive_fpath}")
        sigs_list = list_sigs(archive_fpath)

        with open(f"sigs.csv", "w") as f:
            header = ",".join(sig_fields)
            f.write(f"{header}\n")
            for sig in sigs_list:
                row = []
                for field in sig_fields:
                    row.append(f"{getattr(sig, field, '')}")
                f.write(",".join(row))
                f.write("\n")

    elif options.get("sig_age", None):
        # python .\main.py archive -f .\files\ips-content.ns_23.147.10_amd64.deb
        # --sig_age .\files\Snort3_rules_timetag.txt
        LOGGER.debug(f"Calculating age of security-category signatures in "
                     f"{archive_fpath} with reference to creation timestamps in "
                     f"{options['sig_age']}")
        sig_objs = determine_sigs_age(archive_fpath, options["sig_age"])
        sig_fields = ["signature_id", "name", "creation_timestamp",
                      "signature_age"]

        with open(f"sigs_age.csv", "w") as f:
            header = "SID, Sig name, Sig Creation date, Age"
            f.write(f"{header}\n")
            for sig in sig_objs:
                row = []
                for field in sig_fields:
                    row.append(f"{getattr(sig, field, '')}")
                f.write(",".join(row))
                f.write("\n")

    elif options.get("cvss", None):
        # python .\main.py archive --file .\files\ips-content.ns_23.147.10_amd64.deb
        # --cvss .\files\cve.res
        LOGGER.debug(f"Determining CVSS scores of security-category signatures in "
                     f"{archive_fpath} with reference to metadata in "
                     f"{options['cvss']}")
        sig_objs = determine_cvss_scores(archive_fpath, options["cvss"])
        sig_fields = ["signature_id", "cvss"]

        with open(f"sigs_cvss.csv", "w") as f:
            header = "SID, CVSS"
            f.write(f"{header}\n")
            for sig in sig_objs:
                row = []
                for field in sig_fields:
                    row.append(f"{getattr(sig, field, '')}")
                f.write(",".join(row))
                f.write("\n")

    elif options.get("pocs", None):
        # python .\main.py archive --file .\files\ips-content.ns_23.147.10_amd64.deb
        # --pocs .\files\poc.res
        LOGGER.debug(f"Determining POC links of security-category signatures in "
                     f"{archive_fpath} with reference to metadata in "
                     f"{options['pocs']}")
        sig_objs = determine_pocs_links(archive_fpath, options["pocs"])
        sig_fields = ["signature_id", "pocs"]

        with open(f"sigs_pocs.csv", "w") as f:
            header = "SID, POCS"
            f.write(f"{header}\n")
            for sig in sig_objs:
                row = []
                for field in sig_fields:
                    row.append(f"{getattr(sig, field, '')}")
                f.write(",".join(row))
                f.write("\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="processor")

    build_archive_parser = subparsers.add_parser("archive",
                                                 help="Build archive parser")
    build_archive_parser.add_argument(
        "-f", "--file", type=str, default=None,
        help="Path to .deb content build archive"
    )
    build_archive_parser.add_argument(
        "--list", action="store_true", dest="list_sigs",
        help="List security-category rules in content build"
    )
    build_archive_parser.add_argument(
        "--fields", type=str, dest="sig_fields", nargs="+",
        choices=("signature_id", "name", "signature_code"), default="signature_code",
        help="Signature fields to dump"
    )
    build_archive_parser.add_argument(
        "--sig_age", type=str, default=None,
        help="Calculate signature age given the reference signature "
             "creation timestamps"
    )
    build_archive_parser.add_argument(
        "--cvss", type=str, default=None,
        help="Determine CVSS scores associated with a CVE-ID and given SID"
    )
    build_archive_parser.add_argument(
        "--pocs", type=str, default=None,
        help="Determine POC reference links associated with a given SID"
    )

    args = parser.parse_args()

    if args.processor.lower() == "archive":
        process_archive({
            "fpath": args.file,
            "fields": args.sig_fields,
            "list_sigs": args.list_sigs,
            "sig_age": args.sig_age,
            "cvss": args.cvss,
            "pocs": args.pocs,
        })
