import os
import unix_ar
import xtarfile

import logging

logging.basicConfig(level="DEBUG")
LOGGER = logging.getLogger(__name__)


def decompress_deb(input_deb_fpath, out_dir):
    """
    This function decompresses the given .deb archive into the given output
    directory.

    :param input_deb_fpath: On-disk path to the .deb archive
    :type input_deb_fpath: str
    :param out_dir: Directory into which the .deb archive should be decompressed into
    :type out_dir: str
    :return: Status of decompressed, error message if any
    :rtype: bool, dict
    """
    LOGGER.debug(f"Decompressing {input_deb_fpath}")

    # Create the output directory if it doesn't exist
    if not os.path.isdir(out_dir):
        LOGGER.debug(f"{out_dir} doesn't exist. Creating it")
        os.mkdir(out_dir)

    # This decompression will result in three files: control.tar.xz,
    # data.tar.xz and debian-binary
    LOGGER.debug("Starting xz decompression")
    f_ar = unix_ar.open(input_deb_fpath, "r")
    f_ar.extractall(out_dir)
    f_ar.close()
    LOGGER.debug("xz decompression complete")

    # Only data.tar.xz is relevant
    LOGGER.debug("Removing unwanted xz-decompression artifacts")
    os.remove(os.path.join(out_dir, "control.tar.xz"))
    os.remove(os.path.join(out_dir, "debian-binary"))

    # Extract data.tar.xz
    LOGGER.debug("Starting tar decompression")
    with xtarfile.open(os.path.join(out_dir, "data.tar.xz"), "r") as f:
        f.extractall(out_dir)
    LOGGER.debug("tar decompression complete")

    # Remove data.tar.xz
    LOGGER.debug("Removing unwanted tar-decompression artifacts")
    os.remove(os.path.join(out_dir, "data.tar.xz"))

    # Check for expected directory after decompression
    if not os.path.isdir(os.path.join(out_dir, "opt")):
        err_msg = f"Error trying to decompress {input_deb_fpath}. "\
                  "Expected 'opt' sub-directory not found"
        LOGGER.error(err_msg)
        return False, {"error_msg": err_msg}

    LOGGER.debug(f"{input_deb_fpath} successfully decompressed into {out_dir}")
    return True, {}
