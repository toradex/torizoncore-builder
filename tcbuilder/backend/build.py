"""
Backend handling for build subcommand
"""

import json
import os
import copy
import logging
import re
import sys
import shutil
import tempfile

from urllib.parse import urlparse, unquote
from urllib.request import urlretrieve

import jsonschema
import yaml

from tcbuilder.backend.common import progress, get_file_sha256sum
from tcbuilder.backend.expandvars import expand
from tcbuilder.errors import (PathNotExistError, InvalidDataError,
                              InvalidAssignmentError, OperationFailureError,
                              IntegrityCheckFailed, ParseError, ParseErrors)

DEFAULT_SCHEMA_FILE = "tcbuild.schema.yaml"

RELEASE_TO_PROD_MAP = {
    "nightly": "torizoncore-oe-prerelease-frankfurt",
    "monthly": "torizoncore-oe-prerelease-frankfurt",
    "quarterly": "torizoncore-oe-prod-frankfurt"
}
RELEASE_TO_DEVEL_MAP = {
    "nightly": "-devel-",
    "monthly": "-devel-",
    "quarterly": ""
}
RELEASE_TO_BUILD_TYPE_MAP = {
    "nightly": "nightly",
    "monthly": "monthly",
    "quarterly": "release"
}
MAJOR_TO_YOCTO_MAP = {
    5: "dunfell-5.x.y",
    6: "kirkstone-6.x.y"
}
DEFAULT_IMAGE_VARIANT = "torizon-core-docker"

# Assigment regex pre-compiled.
ASSGN_REGEX = re.compile(r"^([a-zA-Z_][a-zA-Z_0-9]*)=(.*)$")

# Possible file name extensions for which parse_remote() will consider the
# inferred file name valid.
ALLOWED_SLUG_EXTS = [".tar", ".zip"]

# Minimum base file name length for which parse_remote() will consider the
# inferred file name valid.
MIN_INFER_FNAME = 8


log = logging.getLogger("torizon." + __name__)


def parse_assignments(assignments):
    """Parse a list of assignment strings in the form KEY=VALUE

    :param assignments: List of strings to be parsed.
    :return: Dictionary with the resulting key-value mapping.
    """

    var_mapping = {}
    for assgn in assignments:
        matches = ASSGN_REGEX.match(assgn)
        if not matches:
            raise InvalidAssignmentError(
                "Variable assignment must follow the format KEY=VALUE "
                f"(in assignment '{assgn}').")
        # log.debug(f"parse_assignments: '{matches.group(1)}' <= '{matches.group(2)}'")
        var_key, var_val = matches.group(1), matches.group(2)
        var_mapping[var_key] = var_val

    return var_mapping


def sanitize_fname(fname, repl="_"):
    """Replace disallowed characters in file names"""
    return re.sub(r"[^\w\.\-\+]", repl, fname)


def parse_remote(remote_str, infer_fname=True):
    """Parse the 'remote' property in the configuration file

    The remote property provides the remote file URL but it may additionally
    indicate the expected SHA-256 checksum of the file.
    """

    parts = urlparse(remote_str)
    if parts.scheme.lower() not in ["ftp", "http", "https"]:
        raise InvalidDataError("Remote must be provided as an FTP or HTTP URL")

    fname = None
    cksum = None
    params_in = parts.params.split(";")
    params_out = []
    for param in params_in:
        # Handle some special parameters.
        matches = re.match(r"sha256sum=([a-fA-F0-9]+)", param)
        if matches:
            cksum = matches.group(1)
            continue
        matches = re.match(r"filename=(.*)", param)
        if matches:
            fname = matches.group(1)
            continue
        params_out.append(param)

    # Rebuild URL without consumed parameters.
    url = parts._replace(params=";".join(params_out)).geturl()

    # If user did not specify a file name, try to determine one from the URL.
    # Note that this is not expected to work always but we need a stable file
    # name in order to be able to find out if the file has already been
    # downloaded. Here we also sanitize the file name just in case.
    if fname is None and infer_fname:
        fname = unquote(os.path.basename(parts.path))
        fname = sanitize_fname(fname) or None
        fparts = os.path.splitext(fname)
        if (len(fparts[0]) >= MIN_INFER_FNAME and fparts[1] in ALLOWED_SLUG_EXTS):
            log.debug(f"Remote file name inferred from slug: {fname}")
        else:
            log.debug("Remote file name could not be inferred from slug")
            fname = None

    return url, fname, cksum


def fetch_remote(url, fname=None, cksum=None, download_dir=None):
    """Fetch a remote file

    :param url: Source URL for the file.
    :param fname: Base name of the file to download (currently required).
    :param cksum: Expected SHA-256 checksum of the file. If the downloaded
                  file checksum does not match it an `IntegrityCheckFailed`
                  exception will be raised.
    :param download_dir: Directory where file should be downloaded to or
                         obtained from if it already exists (TODO).
    """

    # No path allowed: paths should be passed through download_dir.
    if fname:
        assert os.path.basename(fname) == fname, \
            "fetch_remote: file name cannot contain a path"

    if None not in [fname, cksum, download_dir]:
        # If a file in the download directory with correct checksum exists then
        # do not download it again (TODO).
        pass

    elif None not in [fname, download_dir]:
        # If a file in the download directory exists and its checksum matches
        # the one provided by the server then do not download it again.
        # Note that Artifactory provides a header named X-Checksum-Sha256
        # that we could use for that (TODO).
        pass

    # Inner helper function.
    def make_download_fname(fname):
        """Make full name of file to download"""
        des_fname = None
        is_temp = False
        if download_dir and fname:
            # Download directory and file name known: use them.
            des_fname = os.path.join(download_dir, fname)
        elif fname:
            # Only file name is known: place file into temp directory.
            des_fname = os.path.join(tempfile.gettempdir(), fname)
            is_temp = True
        return des_fname, is_temp

    in_fname, is_temp = make_download_fname(fname)

    try:
        # Show progress bar only when outputting to a terminal.
        progress_hook = None
        if sys.stdout.isatty():
            print(f"Fetching URL '{url}' into '{in_fname}'")
            progress_hook = progress
        else:
            log.info(f"Fetching URL '{url}' into '{in_fname}'")

        # Do actual download.
        out_fname, headers = urlretrieve(
            url, filename=in_fname, reporthook=progress_hook)
        log.info("\nDownload Complete!")
        # log.debug(f"Downloaded {out_fname}, headers: {headers}")

        # If we still haven't decided the name of the file, try to determine
        # one from the Content-Disposition header.
        if in_fname is None and "Content-Disposition" in headers:
            new_fname = parse_disposition_header(headers["Content-Disposition"])
            new_fname = sanitize_fname(new_fname)
            new_fname, is_temp = make_download_fname(new_fname)
            log.debug(f"Moving '{out_fname}' to '{new_fname}'")
            shutil.move(out_fname, new_fname)
            out_fname = new_fname

        elif in_fname is None:
            # Currently a temporary name is useless to the program because the
            # file name is used to determine its type. This should be reviewed
            # if the logic in 'images unpack' changes (TODO).
            os.unlink(out_fname)
            raise InvalidDataError(
                "Cannot determine appropriate file name after download!")
    except:
        raise OperationFailureError(f"Could not fetch URL '{url}'")

    log.info(f"Downloaded file name: '{out_fname}'")

    # Ensure checksum matches expected one:
    if cksum is not None:
        file_cksum = get_file_sha256sum(out_fname)
        if cksum != file_cksum:
            raise IntegrityCheckFailed(
                f"Downloaded file sha256sum of '{file_cksum}' does not match "
                f"expected checksum of '{cksum}'")
        log.info("Integrity check was successful!")
    else:
        log.info("No integrity check performed because checksum was not specified.")

    return out_fname, is_temp

def _load_config_file_yaml(config_path):
    """
    Load the YAML configuration file
    """

    # Load the YAML configuration file (user-supplied):
    with open(config_path) as file:
        try:
            config = yaml.load(file, Loader=yaml.FullLoader)
            return config

        except yaml.YAMLError as ex:
            error_exc = ParseError(getattr(ex, "problem", "parsing error"))
            error_exc.set_source(file=config_path)
            if hasattr(ex, "problem_mark"):
                mark = getattr(ex, "problem_mark")
                error_exc.set_source(line=mark.line, column=mark.column)
            raise error_exc


def _load_config_file_json(config_path):
    """
    Load the JSON configuration file
    """

    # Load the JSON configuration file (user-supplied):
    with open(config_path) as file:
        try:
            config = json.load(file)
            return config

        except json.JSONDecodeError as ex:
            error_exc = ParseError(getattr(ex, "msg", "parsing error"))
            error_exc.set_source(file=config_path)
            if hasattr(ex, "doc"):
                error_exc.set_source(line=ex.doc)
            raise error_exc


def parse_config_file(config_path, schema_path=DEFAULT_SCHEMA_FILE, substs=None):
    """Parse a configuration file against the expected schema

    :param config_path: Configuration file (full-path).
    :param schema_path: Schema file.
    :param substs: Dictionary with variables to substitute.
    :return: The contents of the configuration file as a dictionary.
    """

    if not os.path.exists(config_path):
        raise PathNotExistError(
            f"Build configuration file '{config_path}' does not exist.")


    if config_path.endswith(".json"):
        config = _load_config_file_json(config_path)
    elif config_path.endswith(".yaml") or config_path.endswith(".yml"):
        config = _load_config_file_yaml(config_path)

    # Make variable substitutions.
    if substs is not None:
        config = subst_variables(config, substs)

    # Load the YAML schema file (supplied with the tool):
    schemapath = os.path.join(os.path.dirname(__file__), schema_path)
    with open(schemapath) as file:
        schema = yaml.load(file, Loader=yaml.FullLoader)

    # Do the actual validation of configuration against the schema.
    validator = jsonschema.Draft7Validator(schema)
    errors = []
    for error in validator.iter_errors(config):
        error_exc = ParseError(error.message)
        error_exc.set_source(file=config_path, prop=error.path)
        errors.append(error_exc)
    if errors:
        raise ParseErrors("Parsing errors found in configuration file!", payload=errors)

    return config


def make_feed_url(feed_props):
    """Build URL to the input image based on Toradex feed properties"""

    # Update documentation with latest changes to the toradex-feed prop:
    # - major -> version (string, major.minor.patch)
    # - module -> machine
    # - release value 'stable' -> 'quarterly'
    # - build-number (number|string, required) added
    # - build-date (number|string, required except when quarterly) added

    # ---
    # Define each part of the URL - store in a dictionary:
    # ---
    params = {}

    # NOTE: We use assertions below for tests that should never fail
    #       since the schema validation should have caught them before
    #       and we raise exceptions in other cases.
    release_prop = feed_props.get("release")
    if release_prop not in RELEASE_TO_PROD_MAP:
        assert False, "Unhandled release property value"

    distro_prop = feed_props["distro"]
    rt_flag = "-rt" if distro_prop[-3:] == "-rt" else ""

    params["prod"] = RELEASE_TO_PROD_MAP[release_prop]
    params["machine_name"] = feed_props["machine"]
    params["distro"] = distro_prop
    params["variant"] = feed_props.get("variant", DEFAULT_IMAGE_VARIANT)
    params["rt_flag"] = rt_flag

    version_prop = feed_props["version"]
    version_major = int(version_prop.split('.')[0])
    if version_major not in MAJOR_TO_YOCTO_MAP:
        # Raise a parse error instead to allow a better message (TODO)
        # Caller should capture parse error and set file name.
        raise InvalidDataError(
            f"Don't know how to handle a major version of {version_major}")

    params["version"] = feed_props["version"]
    params["yocto"] = MAJOR_TO_YOCTO_MAP[version_major]

    if release_prop not in RELEASE_TO_BUILD_TYPE_MAP:
        assert False, "Unhandled release property value"
    params["build_type"] = RELEASE_TO_BUILD_TYPE_MAP[release_prop]

    # Automatically detect build number and build date based on manifest (TODO)
    build_number_prop = feed_props["build-number"]
    params["build_number"] = build_number_prop

    if release_prop == "quarterly":
        params["build_date"] = ""
    else:
        build_date_prop = feed_props.get("build-date")
        if build_date_prop is None:
            # Raise a parse error instead to allow a better message (TODO)
            raise InvalidDataError("'build-date' must be specified")
        params["build_date"] = build_date_prop

    if release_prop not in RELEASE_TO_DEVEL_MAP:
        assert False, "Unhandled release property value"
    params["devel"] = RELEASE_TO_DEVEL_MAP[release_prop]

    url_format = (
        "https://artifacts.toradex.com/artifactory/{prod}/{yocto}/"
        "{build_type}/{build_number}/{machine_name}/{distro}/{variant}/"
        "oedeploy/{variant}{rt_flag}-{machine_name}-Tezi_{version}"
        "{devel}{build_date}+build.{build_number}.tar"
    )
    name_format = (
        "{variant}{rt_flag}-{machine_name}-Tezi_{version}"
        "{devel}{build_date}+build.{build_number}.tar"
    )

    url = url_format.format(**params)
    filename = name_format.format(**params)

    log.debug(f"Feed URL: {url}")

    return url, filename


def transform_leaves(dct, handler, max_depth=10):
    """Traverse a dictionary invoking 'handler' on all leaf nodes"""

    def _traverse(dct_or_lst, depth=0):
        assert depth < max_depth, "Dictionary is too deeply nested"
        if isinstance(dct_or_lst, dict):
            for key, value in dct_or_lst.items():
                if isinstance(value, (list, tuple, dict)):
                    _traverse(value, depth+1)
                else:
                    dct_or_lst[key] = handler(value)
                    # log.debug(f"Property {key}: '{value}' -> '{dct_or_lst[key]}'")

        elif isinstance(dct_or_lst, (list, tuple)):
            for index, value in enumerate(dct_or_lst):
                if isinstance(value, (list, tuple, dict)):
                    _traverse(value, depth+1)
                else:
                    dct_or_lst[index] = handler(value)
                    # log.debug(f"Property [{index}]: '{value}' -> '{dct_or_lst[index]}'")
        else:
            assert False, "_traverse() error"

    _traverse(dct)


def subst_variables(config, variables):
    """Perform variable substitution on all string-type values

    This function will go over all string-type values contained in the
    dictionary 'config' expanding variables via the expand() function.
    """

    def _replacer(value):
        if isinstance(value, str):
            return expand(value, variables)
        # No change except for string.
        return value

    config = copy.deepcopy(config)
    transform_leaves(config, _replacer)
    return config


# From https://stackoverflow.com/questions/37060344/
# how-to-determine-the-filename-of-content-downloaded-with-http-in-python
#
def parse_disposition_header(header):
    """Simplified parser of Content-Disposition header (RF6266)"""
    # Review this if a full-blown parser is required (TODO).
    # See https://tools.ietf.org/html/rfc6266
    fname = re.findall(r"filename\*?=([^;]+)", header, flags=re.IGNORECASE)
    assert len(fname) == 1, "Failed parsing Content-Disposition header"
    return fname[0].strip().strip('"')
