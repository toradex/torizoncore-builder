"""
Backend handling for platform subcommand
"""

# pylint: disable=too-many-lines

import hashlib
import json
import logging
import os
import re
import sys
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from fnmatch import fnmatchcase
from io import BytesIO, TextIOWrapper
from tempfile import TemporaryDirectory
from urllib.parse import urljoin

import docker.errors
import jsonschema
import requests
import yaml

from tcbuilder.errors import \
    (TorizonCoreBuilderError, InvalidDataError, OperationFailureError,
     FetchError, ParseError, ParseErrors)
from tcbuilder.backend import ostree, sotaops
from tcbuilder.backend.bundle import \
    (DindManager, login_to_registries, show_pull_progress_xterm)
from tcbuilder.backend.build import parse_config_file
from tcbuilder.backend.common import \
    (get_host_workdir, get_own_network, set_output_ownership, run_with_loading_animation,
     validate_compose_file)
from tcbuilder.backend.registryops import \
    (RegistryOperations, SHA256_PREFIX, parse_image_name, platform_matches)

log = logging.getLogger("torizon." + __name__)

JSON_EXT = ".json"
ROOT_META_FILE = "root.json"
TARGETS_META_FILE = "targets.json"
SNAPSHOT_META_FILE = "snapshot.json"
OFFLINE_SNAPSHOT_FILE = "offline-snapshot.json"

DEFAULT_METADATA_MAXLEN = 4 * 1024 * 1024
TARGETS_METADATA_MAXLEN = 16 * 1024 * 1024
OSTREE_PUBLIC_FEED = "https://feeds.toradex.com/ostree"
UNSAFE_FILENAME_CHARS = r'\/:*?"<>|'

RESERVED_LOCKBOX_NAMES = [
    "root", "snapshot", "targets", "timestamp", "offline-snapshot"
]

PROV_IMGREPO_DIRNAME = "repo"
PROV_DIRECTOR_DIRNAME = "director"

UPTANE_SIGN_UPLOAD_TIMEOUT = "60"
TUF_REPO_DIR = "/deploy/tuf-repo"

# SHA256 Hash Regex
HASH_REGEX = re.compile(r"^[0-9a-f]{64}$")

SECBOOT_TECH_PER_MACHINE = {
    "verdin-imx8mp": "hab",
    "verdin-imx8mm": "hab",
    "apalis-imx8": "ahab",
    "apalis-imx6": "hab",
    "colibri-imx8x": "ahab",
    "colibri-imx7-emmc": "hab",
    "colibri-imx6": "hab",
    "colibri-imx6ull-emmc": "hab",
}

FUSE_HWID_SUFFIX = "-fuses"
FUSE_HARDWAREIDS = [
    f"{_mach}{FUSE_HWID_SUFFIX}" for _mach in SECBOOT_TECH_PER_MACHINE
]

FUSE_SCHEMA_FILE = "fuse.schema.yaml"

BOOTLOADER_DD_OPTIONS_PER_MACHINE = {
    "verdin-imx8mp": "seek=0",
    "verdin-imx8mm": "seek=2",
    "verdin-am62": "seek=0",
    "verdin-am62p": "seek=0",
    "apalis-imx8": "seek=0",
    "apalis-imx6": "seek=2",
    "colibri-imx8x": "seek=0",
    "colibri-imx6": "seek=2",
    "colibri-imx6ull-emmc": "seek=2",
    "colibri-imx7-emmc": "seek=2",
}

BOOTLOADER_HWID_SUFFIX = "-bootloader"
BOOTLOADER_HARDWAREIDS = [
    f"{_mach}{BOOTLOADER_HWID_SUFFIX}"
    for _mach in BOOTLOADER_DD_OPTIONS_PER_MACHINE
]

UBOOT_JSON_SCHEMA_FILE = "uboot-schema.json"

DEFAULT_CONNECT_TIMEOUT = int(os.environ.get("DEFAULT_CONNECT_TIMEOUT", "60"))
COMMIT_CHECK_TIMEOUT = int(os.environ.get("COMMIT_CHECK_TIMEOUT", "60"))
FETCH_READ_TIMEOUT = int(os.environ.get("FETCH_READ_TIMEOUT", "60"))
UPDATE_DESC_TIMEOUT = int(os.environ.get("UPDATE_DESC_TIMEOUT", "60"))
UPLOAD_DELTA_TIMEOUT = int(os.environ.get("UPLOAD_DELTA_TIMEOUT", "240"))
PARALLEL_DOWNLOADS = int(os.environ.get("PARALLEL_DOWNLOADS", "10"))


def load_metadata(fname, ftype=None, maxlen=DEFAULT_METADATA_MAXLEN):
    """Load metadata file and determine some of its attributes (size, sha256).

    :param fname: Name of the file to load.
    :param ftype: Type of the file for parsing purposes ("json" or "yaml"). If
                  not specified, this will default to "json" unless the file
                  name extension is ".yml" or ".yaml".
    :param maxlen: Maximum length of the file; raise exception if length is
                   exceeded.
    """

    # Load all file into memory.
    with open(fname, "rb") as fileh:
        data = fileh.read(maxlen + 1)
        assert len(data) <= maxlen, \
            f"File {fname} is larger than {maxlen} bytes (giving up)"

    # Wrap data into a text stream for loading.
    data_as_stream = BytesIO(data)
    data_as_text = TextIOWrapper(data_as_stream, encoding="utf-8")

    data_sha256_ = hashlib.sha256()
    data_sha256_.update(data)
    data_sha256 = data_sha256_.hexdigest()

    log.debug(f"File {fname}: sha256sum: {data_sha256}")

    # Determine parser to be used:
    if ftype is None:
        if os.path.splitext(fname)[1].lower() in [".yml", ".yaml"]:
            ftype = "yaml"
        else:
            ftype = "json"

    # Parse file.
    if ftype == "json":
        parsed = json.load(data_as_text)
    else:
        parsed = yaml.safe_load(data_as_text)

    return {
        "file": fname, "size": len(data), "sha256": data_sha256, "parsed": parsed
    }


def check_commit_present(ostree_url, commit_sha256, access_token=None):
    """Determine if the given commit is present at an OSTree repo

    :param ostree_url: Base URL to OSTree repo.
    :param commit_sha256: Hex digest of the commit (must be lower-case).
    :param access_token: If specified, the bearer token to access the resource
                         at the server.
    """

    # Build URL of OSTree commit:
    url = urljoin(
        ostree_url + "/",
        f"objects/{commit_sha256[:2]}/{commit_sha256[2:]}.commit")

    # Try to access resource using the HEAD method.
    if access_token:
        assert url.lower().startswith("https://")
        res = requests.head(
            url, allow_redirects=True,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=(DEFAULT_CONNECT_TIMEOUT, COMMIT_CHECK_TIMEOUT))
    else:
        res = requests.head(
            url, allow_redirects=True,
            timeout=(DEFAULT_CONNECT_TIMEOUT, COMMIT_CHECK_TIMEOUT))

    if res.status_code == requests.codes["ok"]:
        return True

    if res.status_code == requests.codes["not_found"]:
        return False

    raise InvalidDataError(
        "Unexpected status code when looking for commit: "
        f"code={res.status_code}, url={url}")


def do_fetch_ostree_target(target, sha256, ostree_url, images_dir, access_token=None):
    """Helper to fetch a given commit from a specified OSTree repo"""

    # Evaluate using libostree for the work done by this function (FUTURE).
    # Create a local repo.
    repo_dir = os.path.join(images_dir, "ostree")
    if not os.path.exists(repo_dir):
        log.debug(f"Initializing OSTree at '{repo_dir}'")
        os.mkdir(repo_dir)
        subprocess.run(
            ["ostree", "init", "--repo", repo_dir, "--mode=archive"],
            check=True)
    else:
        log.debug(f"Reusing existing OSTree repo at '{repo_dir}'")

    # Add a temporary remote.
    remote_name = "tmpremote"
    subprocess.run(
        ["ostree", "remote", "add", remote_name,
         "--repo", repo_dir, ostree_url, "--no-gpg-verify", "--force"],
        check=True)

    # Pull our hashref.
    pull_cmd = ["ostree", "pull", "--repo", repo_dir, remote_name, sha256]
    if access_token:
        # Add authorization header (that is supposed to be valid for hours) (FIXME):
        pull_cmd.extend([
            "--http-header", f'Authorization=Bearer {access_token}'
        ])
    log.debug(f"Running {' '.join(pull_cmd)}")
    subprocess.run(pull_cmd, check=True)

    # Create a ref named after the target.
    try:
        subprocess.run(
            ["ostree", "refs", "--repo", repo_dir, "--create", target, sha256, "--force"],
            check=True, capture_output=True, text=True)

    except subprocess.CalledProcessError as called_process_error:
        # Setting the ref name is nice but not strictly required; it might fail if
        # the target name does not match the naming pattern allowed by OSTree. A
        # possible improvement would be to sanitize the name to be in accordance
        # with the allowed pattern which can be seen in OSTree's source code, file
        # ostree-core.c, macro `OSTREE_REF_REGEXP`.
        log.debug(called_process_error.stderr)
        log.debug("Could not create ref according to Uptane target name (non-fatal)")

    # Remove remote.
    subprocess.run(
        ["ostree", "remote", "delete", remote_name, "--repo", repo_dir],
        check=True)


def fetch_ostree_target(target, sha256, ostree_url, images_dir, *,
                        access_token=None, name=None, version=None):
    """Fetch commit from the specified OSTree repo falling back to a public one

    :param target: Target as it appears in the Uptane metadata.
    :param sha256: ID of the commit.
    :param ostree_url: Base URL of the OSTree repository.
    :param images_dir: Directory where images should be stored. This function
                       will create a sub-directory to hold the OSTree repo.
    :param access_token: OAuth2 access token giving access to the OSTree repo.
    :param name: Name of target visible to the user as it appears in the Uptane
                 metadata.
    :param version: Version of the target visible to the user as it appears in
                    the Uptane metadata.
    """

    log.info(f"Handling OSTree target '{target}'")

    # Try to find commit on the user's repo first and then on the public feed.
    log.debug(f"Looking for commit {sha256} on the user's repo")
    server_url, server_token = None, None
    commit_present = check_commit_present(
        ostree_url, commit_sha256=sha256, access_token=access_token)
    if commit_present:
        log.info(f"Commit {sha256} found on the user's repo")
        server_url = ostree_url
        server_token = access_token
    else:
        log.debug(f"Looking for commit {sha256} on public feed")
        # For security reasons, we must not use the access-token with the public feed:
        commit_present = check_commit_present(
            OSTREE_PUBLIC_FEED, commit_sha256=sha256)
        if commit_present:
            server_url = OSTREE_PUBLIC_FEED
            server_token = None

    if not commit_present:
        raise TorizonCoreBuilderError(
            f"Could not find commit {sha256} on user's repo or on public feed")

    log.info(f"Fetching OSTree commit {sha256} from {server_url}...")
    log.info(f"Uptane info: target '{name}', version: '{version}'")
    return do_fetch_ostree_target(
        target, sha256, server_url, images_dir, access_token=server_token)


def fetch_validate(url, fname, dest_dir, *,
                   sha256=None, length=None, access_token=None, parse=None):
    """Fetch and possibly validate a given resource (file)

    :param url: Full URL to the resource (file).
    :param fname: Local name of the file (without a path).
    :param dest_dir: Destination directory for the local file.
    :param sha256: If specified, the required sha256 of the file.
    :param length: If specified, the required length in bytes of the file.
    :param access_token: If specified, the bearer token to access the resource
                         at the server.
    :param parse: If set to "json" the file will be parsed as JSON and the
                  result returned by the function (in case of success).
    """

    # Make sure there are no unsafe characters in the filename:
    # https://superuser.com/questions/358855/
    # what-characters-are-safe-in-cross-platform-file-names-for-linux-windows-and-os
    #
    # To support offline bootloader updates, we need to allow / in the filename.
    # In this case, we will create the directory represented as needed. We add a
    # check for `../` to protect against directory traversal, but it should not be
    # a great concern: this is user-supplied data, and the directory traversal
    # would be on the user's own machine.

    assert all(ch not in UNSAFE_FILENAME_CHARS.replace('/', '') for ch in fname) \
        and "../" not in fname, f"Target '{fname}' contains unsafe characters"

    # Fetch the file:
    if access_token:
        assert url.lower().startswith("https://")
        res = requests.get(
            url, headers={"Authorization": f"Bearer {access_token}"},
            timeout=(DEFAULT_CONNECT_TIMEOUT, FETCH_READ_TIMEOUT))
    else:
        res = requests.get(
            url, timeout=(DEFAULT_CONNECT_TIMEOUT, FETCH_READ_TIMEOUT))

    if res.status_code != requests.codes["ok"]:
        raise FetchError(
            f"Could not fetch file '{fname}' from '{url}'",
            status_code=res.status_code)

    if length is not None and len(res.content) != length:
        raise InvalidDataError(
            f"Downloaded file '{fname}' has wrong length "
            f"(actual={len(res.content)}, expected={length} bytes)")

    # Determine the sha256 of the data:
    content_sha256_ = hashlib.sha256()
    content_sha256_.update(res.content)
    content_sha256 = content_sha256_.hexdigest()

    if sha256 is not None and content_sha256 != sha256:
        raise InvalidDataError(
            f"Downloaded file '{fname}' has wrong sha256 checksum "
            f"(actual='{content_sha256}', expected='{sha256}')")

    # Write file into destination:
    fname = os.path.join(dest_dir, fname)
    os.makedirs(os.path.dirname(fname), exist_ok=True)
    with open(fname, "wb") as cmph:
        cmph.write(res.content)
    log.debug(f"Written file '{fname}' with {length} bytes, sha256='{sha256}'")

    ret = None
    if parse is None:
        pass
    elif parse == "json":
        ret = json.loads(res.text)
    elif parse == "yaml":
        ret = yaml.safe_load(res.text)
    else:
        assert False, f"Bad argument to fetch_validate(): parse={parse}"

    return ret


def fetch_file_target(target, repo_url, images_dir, *,
                      sha256=None, length=None, access_token=None, parse=None,
                      name=None, version=None, custom_uri=None):
    """Fetch a generic file target from the TUF repo

    :param target: Target as it appears in the Uptane metadata.
    :param repo_url: Base URL of the TUF repository as it appears in the
                     credentials file.
    :param images_dir: Directory where images would be stored.
    :param sha256: SHA256 checksum of the target.
    :param length: Length of the target in bytes.
    :param access_token: OAuth2 access token giving access to the TUF repo at
                         the OTA server.
    :param parse: How to parse the file (if not None): "json" or "yaml".
    :param name: Name of target visible to the user as it appears in the Uptane
                 metadata.
    :param version: Version of the target visible to the user as it appears in
                    the Uptane metadata.
    :custom_uri: Full URL to file when stored outside of the OTA server.
    """

    # Build URL to file at OTA server:
    if custom_uri:
        url = custom_uri
        access_token = None
    else:
        url = urljoin(repo_url + "/", f"api/v1/user_repo/targets/{target}")

    log.info(f"Fetching target '{target}' from '{url}'...")
    log.info(f"Uptane info: target '{name}', version: '{version}'")

    return fetch_validate(
        url, target, images_dir,
        sha256=sha256, length=length, access_token=access_token, parse=parse)


def get_referenced_images(compose):
    """Determine all the images being referenced by a docker-compose file.

    :param compose: Parsed docker-compose file as a dictionary.
    :return: A dictionary where the key is the service name and the value is a tuple
             (image, platform); image is the image name as referenced in the
             docker-compose file; platform may be None if no platform was explicitly
             defined in the compose file.
    """
    assert "services" in compose, \
        "Section 'services' not found in docker-compose file"
    services = compose["services"]

    image_per_service = {}
    for svc_name, svc_spec in services.items():
        assert "image" in svc_spec, \
            f"No 'image' specified for service {svc_name}"
        image = svc_spec["image"]
        image_platform = svc_spec.get("platform")
        parsed_name = parse_image_name(image)
        assert parsed_name.tag.startswith(SHA256_PREFIX), \
            f"Image '{image}' not specified by digest"
        image_per_service[svc_name] = \
            (parsed_name.get_name_with_tag(), image_platform)

    log.debug(f"Images being used in docker-compose: {image_per_service}")

    return image_per_service


def fetch_manifests(images, manifests_dir,
                    req_platforms=None, validate=True, verbose=True):
    """Fetch all manifests for the given images.

    :param images: list of image/repo names to fetch (as used in a `docker pull`).
    :param manifests_dir: Directory where to store the manifests.
    :param req_platforms: List of platforms for fetching Docker images (used when
                          not specified in the docker-compose file).
    :param validate: Whether or not to check if each manifest file has a sha256
                     checksum matching the expected one.
    :param verbose: Show verbose output.
    :return: Dictionary where the key is the image name as provided in `images`
             and the value is a list where each object is another dictionary
             with fields:
             - "type": "manifest" or "manifest-list"
             - "name": name of image such as "ubuntu" or "fedora/httpd"
             - "digest": digest of the manifest such as "sha256:123..."
             - "platform": platform as a slash separated string in the form
                           "<os>[/<architecture>[/<variant>]]"
             - "manifest-file": name of the manifest file where data is stored
    """

    digests_cache = set()
    manifests_per_image = {}
    for image in images:
        if verbose:
            log.info(f"\nFetching manifests for {image}...")
        image_parsed = parse_image_name(image)

        ops = RegistryOperations(image_parsed.registry)
        digests_saved, manifests_info = ops.save_all_manifests(
            image_parsed.get_name_with_tag(), manifests_dir,
            platforms=req_platforms,
            val_digest=validate)
        digests_cache.update(digests_saved)

        # Use cache to avoid fetching manifest multiple times (FUTURE).
        # This would be relevant only if the digest is referenced by the
        # manifest-list and also directly: this is expected to be rare.

        manifests_per_image[image] = manifests_info

    # log.debug(f"manifests_per_image: {json.dumps(manifests_per_image)}")
    if verbose:
        log.debug("\n=> Manifests per image:")
        for image, manifests_info in manifests_per_image.items():
            log.debug(f"{image}:")
            for man_info in manifests_info:
                log.debug(f" * {man_info['digest']} [{man_info['type']}]")
                log.debug(f"   in {man_info['manifest-file']}")

    return manifests_per_image


def get_compatible_images(manifests, platform, sort=True):
    """Select compatible images in a manifest list.

    The returned list has the same form as in the input but contains
    only the compatible manifests (possibly sorted).

    :param manifests: A list like this: [{"manifest":., "digest":., "platform"}, ...]
    :param platform: Desired platform.
    :param sort: Whether or not to list the manifest list in descending order
                 of specificity.
    """
    # log.debug(f"get_compatible_images() manifests: {json.dumps(manifests)}")
    manifests_with_grade = []
    for man in manifests:
        ret, grade = platform_matches(platform, man["platform"], ret_grade=True)
        if ret:
            manifests_with_grade.append((grade, man))

    if sort:
        manifests_with_grade.sort(key=lambda elem: elem[0], reverse=True)
        if len(manifests_with_grade) >= 2:
            log.debug(f"manifests_with_grade: {manifests_with_grade}")
            assert manifests_with_grade[0][0] < manifests_with_grade[1][0], \
                "There are multiple images equally appropriate for platform"

    return list(mwg[1] for mwg in manifests_with_grade)


# pylint: disable-next=too-many-locals
def select_images(image_platform_pairs, manifests_per_image, *,
                  req_platforms=None, verbose=True):
    """Determine all single-platform/platform-independent image references."""

    images_selection = []
    images_selection_per_image = []
    for req_image, req_platform in image_platform_pairs:
        if req_image not in manifests_per_image:
            assert False, \
                f"Requested image {req_image} not in the fetched manifests!"

        # Get manifests available for requested image (exclude manifest lists):
        manifests_all = manifests_per_image[req_image]
        manifests = [man for man in manifests_all if man["type"] == "manifest"]
        multi_platform = any(item["type"] == "manifest-list" for item in manifests_all)
        assert manifests, f"No manifest for image {req_image}"

        cur_selection = []
        if req_platform is None:
            # ---
            # No specific platform requested in docker-compose:
            # ---
            if multi_platform and req_platforms is None:
                # Multi-platform image and no default platform defined (select all):
                for child in manifests:
                    if child["platform"] != "unknown/unknown":
                        cur_selection.append(
                            ((req_image, req_platform), child["digest"], child["platform"]))

            elif multi_platform and req_platforms is not None:
                # Multi-platform image and default platforms defined (select only them):
                # Note: this should be the usual case with multi-platform images.
                for _plat in req_platforms:
                    _avail = get_compatible_images(manifests, _plat)
                    assert _avail, \
                        (f"There are no images matching platform '{_plat}' "
                         f"for '{req_image}'")
                    # The first one is the "most compatible" one.
                    _sel = _avail[0]
                    cur_selection.append(
                        ((req_image, req_platform), _sel["digest"], _sel["platform"]))

            else:
                # Not a multi-platform image (select the one available):
                # Note: this should be the usual case with single-platform /
                #       platform-independent images.
                _sel = manifests[0]
                cur_selection.append(
                    ((req_image, req_platform), _sel["digest"], _sel["platform"]))
        else:
            # ---
            # Specific platform requested in docker-compose (it must be available).
            # ---
            if multi_platform:
                # Multi-platform image (select best match):
                _avail = get_compatible_images(manifests, req_platform)
                assert _avail, \
                    (f"There are no images matching platform '{req_platform}' "
                     f"for '{req_image}'")
                # The first one is the "most compatible" one.
                _sel = _avail[0]
                cur_selection.append(
                    ((req_image, req_platform), _sel["digest"], _sel["platform"]))
            else:
                # Not a multi-platform image (select the one available):
                _sel = manifests[0]
                cur_selection.append(
                    ((req_image, req_platform), _sel["digest"], _sel["platform"]))

        images_selection_per_image.append(((req_image, req_platform), cur_selection))
        images_selection.extend(cur_selection)

    if verbose:
        log.info("\n=> Digests selected per image:")
        for (req_image, req_platform), cur_selection in images_selection_per_image:
            _plattxt = f", platform '{req_platform}'" if req_platform else ""
            log.info(f"{req_image}{_plattxt}:")
            for sel in cur_selection:
                log.info(f" * {sel[1]} [{sel[2]}]")

    # At this point `images_selection` is a list like this:
    # [((image, platform), <selected-digest>), ...]
    log.debug(f"images_selection: {images_selection}")

    return images_selection


def select_unique_images(image_platform_pairs, manifests_per_image, *,
                         req_platforms=None, verbose=True):
    """Determine all single-platform/platform-independent image references."""

    images_selection = select_images(
        image_platform_pairs, manifests_per_image, req_platforms=req_platforms)

    # Determine unique images:
    images_selection_unique = set()
    for (sel_image, _sel_plat), sel_digest, _sel_plat in images_selection:
        image_spec = "{0}@{1}".format(sel_image.split("@")[0], sel_digest)
        images_selection_unique.add((image_spec, sel_digest))

    if verbose:
        log.info("\n=> Unique images selected:")
        for sel in sorted(images_selection_unique):
            log.info(f" * {sel[0]}")

    return images_selection_unique


def _apply_skopeo_canon_wkaround(tbdir, image_spec):
    """Apply workarounds for the Skopeo image name canonicalization

    Unlike "docker save", the "skopeo copy" command canonicalizes the names of
    the images that go inside the generated tarball. This is incompatible with
    the validation code that runs inside Aktualizr. To deal with it we undo the
    operation by replacing the canonical names back with the original names as
    referenced by the compose file.
    """

    # ---
    # Fix manifest file:
    # ---
    manifest_path = os.path.join(tbdir, "manifest.json")
    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8") as fhandle:
            manifest_data = json.load(fhandle)

        log.debug(f"Original manifest data: {manifest_data}")

        try:
            # Manifest metadata would look like this:
            #
            # [{'Config': '9cad51f33b0fxxxxxxxxxxxx.json',
            #   'RepoTags': ['docker.io/library/debian:digest_sha256_5c7562ee9fcfxxxxxxxx'],
            #   'Layers': ['58f07f898f87xxxxxxxxxxxx.tar']}]
            #
            # and we want it to become:
            #
            # [{'Config': '9cad51f33b0fxxxxxxxxxxxx.json',
            #   'RepoTags': [<image_spec>],
            #   'Layers': ['58f07f898f87xxxxxxxxxxxx.tar']}]
            #
            assert len(manifest_data) == 1
            assert len(manifest_data[0]["RepoTags"]) == 1
            _tag = manifest_data[0]["RepoTags"][0]
            assert _tag[_tag.index(":digest_"):] == image_spec[image_spec.index(":digest_"):]
            manifest_data[0]["RepoTags"] = [image_spec]

        except (KeyError, IndexError, ValueError, AssertionError) as _error:
            # pylint: disable-next=raise-missing-from
            raise TorizonCoreBuilderError(
                f"Couldn't parse manifest metadata from '{tbdir}'")

        log.debug(f"Transformed manifest data: {manifest_data}")

        with open(manifest_path, "w", encoding="utf-8") as fhandle:
            json.dump(manifest_data, fhandle, separators=(",", ":"))

    # ---
    # Fix repositories file:
    # ---
    repos_path = os.path.join(tbdir, "repositories")
    if os.path.exists(repos_path):
        with open(repos_path, "r", encoding="utf-8") as fhandle:
            repos_data = json.load(fhandle)

        log.debug(f"Original repositories data: {repos_data}")
        try:
            # Repositories metadata would look like this:
            #
            # {'docker.io/library/debian':
            #    {'digest_sha256_5c7562ee9fcfxxxxxxxxxxxx':'a56935c728c6xxxxxxxxxxxx'}}
            #
            # and we want it to become:
            #
            # {'<image_spec (without the tag)>':
            #    {'digest_sha256_5c7562ee9fcfxxxxxxxxxxxx':'a56935c728c6xxxxxxxxxxxx'}}
            #
            assert len(repos_data) == 1
            assert len(repos_data.keys()) == 1
            _repo, _digdict = next(iter(repos_data.items()))
            assert len(_digdict) == 1
            _tag, _value = next(iter(_digdict.items()))
            assert _tag == image_spec[image_spec.index(":digest_")+1:]
            _newrepo = image_spec[:image_spec.index(":digest")]
            repos_data[_newrepo] = _digdict
            del repos_data[_repo]

        except (KeyError, IndexError, ValueError, AssertionError) as _error:
            # pylint: disable-next=raise-missing-from
            raise TorizonCoreBuilderError(
                f"Couldn't parse repositories metadata from '{tbdir}'")

        log.debug(f"Transformed repositories data: {repos_data}")

        with open(repos_path, "w", encoding="utf-8") as fhandle:
            json.dump(repos_data, fhandle, separators=(",", ":"))


def _apply_aktualizr_blkread_wkaround(tbdir):
    """Workaround for bug found in image loading in Aktualizr.

    Aktualizr loads Lockbox image tarballs in blocks of 256K and it performs
    two passes over each tarball. Since the method for loading a tarball is
    different in each pass, it has been found that sometimes there is a
    mismatch in the apparent size of the tarball file causing the Lockbox
    loading to fail. In particular, this happens when the tarball has a size
    slightly above a multiple of 256K. This seems to happen because the first
    pass uses libarchive which stops the reading preemptively without reading
    the end of the file (which is expected to have padding bytes only) while
    the second pass does not go through libarchive and always reads the whole
    file.

    To prevent this bug on Aktualizr from ever being hit, here we increase the
    size of a tarball when its size is slightly above a multiple of 256K.
    """

    # Estimate tarball size:
    tbs = 512
    totsize = 0
    for fname in os.listdir(tbdir):
        path = os.path.join(tbdir, fname)
        if os.path.isdir(path):
            fsize = tbs
            psize = tbs
        else:
            fsize = os.stat(path).st_size
            psize = tbs + ((fsize + tbs - 1) // tbs) * tbs
        totsize += psize

    # As per Wikipedia: The end of an archive is marked by *at least* two consecutive
    # zero-filled records. The final block of an archive is padded out to full length
    # with zeros.
    totsize += 2048 + 1024

    log.debug(f"Estimated image tarball size for '{tbdir}': {totsize}")

    # Aktualizr processes the file in blocks of 256K and we want to avoid a small block
    # at the end to prevent a bug from showing up. For that, we add a dummy file to the
    # tarball when the estimated size is close to a multiple of 256K.
    procbs = 256 * 1024
    if (totsize % procbs < 8192) or (procbs - (totsize % procbs) < 8192):
        log.debug(f"Adding dummy file to '{tbdir}'.")
        dummy_content = "\n" * (4 * 8192)
        with open(os.path.join(tbdir, "xdummy_"), "w", encoding="utf-8") as dummy_file:
            dummy_file.write(dummy_content)
    else:
        log.debug(f"No need to add dummy file to '{tbdir}'.")


def amend_image_tarball(image_fname, image_spec, skopeo_generated=True):
    # Apply the workaround for Skopeo canonicalizing the image names which
    # prevents the loading by Aktualizr since the names are validated against
    # the docker-compose file.
    canon_wkaround = (skopeo_generated and
                      os.environ.get("APPLY_SKOPEO_CANON_WKAROUND", "1") == "1")

    # Apply the workaround for a bug in the Docker image validation which happens if the image is
    # slightly bigger than a multiple of the block reading size (256KB).
    blkread_wkaround = os.environ.get("APPLY_AKTUALIZR_BLKREAD_WKAROUND", "1") == "1"

    if not (canon_wkaround or blkread_wkaround):
        log.debug("No fixes required to the generated Lockbox tarball")

    image_fname_new = image_fname + "_"
    tbdir = os.path.splitext(image_fname)[0] + "_"
    try:
        # Unpack the tarball:
        log.debug(f"Unpacking '{image_fname}' into '{tbdir}'")
        shutil.rmtree(tbdir, ignore_errors=True)
        os.mkdir(tbdir)
        subprocess.check_output([
            "tar", "--numeric-owner", "--preserve-permissions",
            "-xvf", os.path.abspath(image_fname), "-C", tbdir
        ])

        if canon_wkaround:
            _apply_skopeo_canon_wkaround(tbdir, image_spec)
        if blkread_wkaround:
            _apply_aktualizr_blkread_wkaround(tbdir)

        # Repack files into a tarball:
        log.debug(f"Repacking '{tbdir}' into '{image_fname_new}'")
        subprocess.check_output([
            "tar", "--numeric-owner", "--preserve-permissions",
            "-cvf", os.path.abspath(image_fname_new), "-C", tbdir,
            *sorted(os.listdir(tbdir))
        ])

        log.debug(f"Replacing '{image_fname_new}' -> '{image_fname}'")
        os.replace(image_fname_new, image_fname)

    finally:
        shutil.rmtree(tbdir, ignore_errors=True)


def save_image_tarball_docker(dind_client, image_spec, image_fname):
    """Build tarball via `docker image save image:tag > output.tar`

    :param dind_client: Docker API client object.
    :param image_spec: Image specification such as "hello-world:latest".
    :param image_fname: Tarball file to generate such as "/a/b/output.tar".
    """
    image_obj = dind_client.images.get(image_spec)
    with open(image_fname, "wb") as outf:
        for image_data in image_obj.save(named=True):
            outf.write(image_data)


def save_image_tarball_skopeo(dind_env, image_spec, image_fname):
    """Build tarball via `skopeo copy <image> docker-archive:<file>:...`

    :param dind_env: Dictionary with environment variables specifying how to
                     access the desired Docker host.
    :param image_spec: Image specification such as "hello-world:latest".
    :param image_fname: Tarball file to generate such as "/a/b/output.tar".
    """
    cmd = ["skopeo", "copy"]

    # Ensure Docker v2 Schema 2 is always used.
    cmd += ["--format", "v2s2"]

    # skopeo does not handle the usual host specification environment variables
    # used by the Docker client CLI; here we translate them into parameters
    # suitable for the program:
    if dind_env.get("DOCKER_HOST"):
        cmd += ["--src-daemon-host", dind_env["DOCKER_HOST"]]
    if dind_env.get("DOCKER_CERT_PATH"):
        cmd += ["--src-cert-dir", dind_env["DOCKER_CERT_PATH"]]
    if dind_env.get("DOCKER_TLS_VERIFY"):
        # Any non-empty string enables TLS (following Docker's behavior).
        cmd += ["--src-tls-verify"]

    cmd += [f"docker-daemon:{image_spec}",
            f"docker-archive:{image_fname}:{image_spec}"]

    res = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if res.returncode != 0:
        log.error(res.stderr)
        raise TorizonCoreBuilderError(
            f"Error: failed to generate image tarball via skopeo for '{image_fname}'.")


# pylint: disable-next=too-many-locals,too-many-statements
def build_docker_tarballs(unique_images, target_dir, host_workdir, *,
                          verbose=True, dind_params=None, dind_env=None):
    """Build the docker tarballs of a lockbox image

    :param unique_images: Iterable giving the pairs (image, digest) for which
                          to generate the tarballs; `image` should be the image
                          name referencing the desired image locally.
    :param target_dir: Directory where to write the tarballs.
    :param host_workdir: Working directory location on the Docker Host (the
                         system where dockerd we are accessing is running).
    :param verbose: Whether to show verbose output/progress information.
    :param dind_params: Parameters to pass to Docker-in-Docker (list).
    :param dind_env: Environment to pass to Docker-in-Docker (dict).
    """

    show_progress = True
    if verbose:
        _term = os.environ.get('TERM')
        if not sys.stdout.isatty():
            show_progress = False
        elif not (_term.startswith('xterm') or _term.startswith('rxvt')):
            show_progress = False

    network = get_own_network()
    manager = DindManager(target_dir, host_workdir)
    tarballs = None
    cacerts = RegistryOperations.get_cacerts()
    logins = RegistryOperations.get_logins()

    try:
        # Start DinD container on host.
        manager.start(network, dind_params=dind_params, dind_env=dind_env)
        manager.add_cacerts(cacerts)
        # Get DinD client to be used on the pulling operations.
        dind_client = manager.get_client()
        dind_client_env = manager.get_client_env()
        if dind_client is None:
            return None
        # Login to all registries before trying to fetch anything.
        if logins:
            login_to_registries(dind_client, logins)

        # Fetch the containers:
        tarballs = []
        for image_spec, image_digest in unique_images:
            assert image_digest.startswith(SHA256_PREFIX)

            # Fetch image:
            log.info(f"Fetching container image {image_spec}")
            if show_progress:
                # Use low-level API to get progress information.
                res_stream = dind_client.api.pull(image_spec, stream=True, decode=True)
                show_pull_progress_xterm(res_stream)
                image_obj = dind_client.images.get(image_spec)
            else:
                # Use high-level API (no progress info).
                image_obj = dind_client.images.pull(image_spec)

            # Set appropriate tag that will be saved in the `docker save` tarball.
            image_spec_parts = image_spec.split("@")
            assert len(image_spec_parts) == 2, \
                f"Image name {image_spec} does not conform with format name@digest"
            image_spec_tag = "digest_" + image_digest.replace(":", "_")
            image_obj.tag(image_spec_parts[0], image_spec_tag)

            # Re-get the image with the new tag.
            image_spec_new = f"{image_spec_parts[0]}:{image_spec_tag}"
            image_obj = dind_client.images.get(image_spec_new)

            # Name tarball after the image digest:
            image_fname = image_digest[len(SHA256_PREFIX):] + ".tar"
            image_fname = os.path.join(target_dir, image_fname)

            log.info(f"Saving {image_spec}\n"
                     f"  into {image_fname}")

            if os.path.exists(image_fname):
                # Sanity check: images in a Lockbox should be unique.
                raise TorizonCoreBuilderError(
                    f"Container image file '{image_fname}' already exists")

            tar_generator = os.environ.get("LOCKBOX_TARBALL_GENERATOR", "skopeo")
            if tar_generator == "docker":
                save_image_tarball_docker(dind_client, image_spec_new, image_fname)
                amend_image_tarball(image_fname, image_spec_new, skopeo_generated=False)
            elif tar_generator == "skopeo":
                save_image_tarball_skopeo(dind_client_env, image_spec_new, image_fname)
                amend_image_tarball(image_fname, image_spec_new, skopeo_generated=True)
            else:
                raise TorizonCoreBuilderError(
                    "Unknown generator set through variable LOCKBOX_TARBALL_GENERATOR "
                    f"({tar_generator})")

            tarballs.append({
                "image_spec": image_spec,
                "image_spec_tag": image_spec_tag,
                "image_fname": image_fname
            })

        # Done fetching the containers.
        log.debug("Done fetching and saving images!")

    except docker.errors.APIError as exc:
        raise OperationFailureError(
            f"Error: container images download failed: {str(exc)}") from exc

    finally:
        manager.stop()

    if tarballs and verbose:
        log.info("\n=> Tarball summary:")
        for tarball in tarballs:
            log.info(f"{tarball['image_fname']}:")
            log.info(f" * tagged: {tarball['image_spec_tag']}")
            log.info(f" * image:  {tarball['image_spec']}")

    return tarballs


# pylint: disable-next=too-many-arguments,too-many-locals
def fetch_compose_target(target, repo_url, images_dir, metadata_dir, *,
                         sha256=None, length=None, req_platforms=None,
                         access_token=None, name=None, version=None,
                         dind_params=None, dind_env=None, custom_uri=None):
    """Fetch compose file target from the TUF repo along with referenced artifacts

    Parameter `req_platforms` should be a list of the platforms to select
    by default for the Docker images. For the other parameters, see
    :func:`fetch_file_target`.
    """

    # Fetch the docker-compose file.
    log.info(f"Fetching docker-compose target '{target}'")
    compose = fetch_file_target(
        target, repo_url, images_dir,
        sha256=sha256, length=length, access_token=access_token, parse="yaml",
        name=name, version=version, custom_uri=custom_uri)

    # Get the list of images being referenced by the compose-file with their
    # requested platforms.
    image_per_service = get_referenced_images(compose)
    images = {img for img, _plat in image_per_service.values()}

    # Fetch the manifests of all images.
    manifests_dir = os.path.join(metadata_dir, sha256 + ".manifests")
    os.mkdir(manifests_dir)
    manifests_per_image = fetch_manifests(
        images, manifests_dir, req_platforms=req_platforms)

    # Determine (image, platform) pairs referenced in the compose file.
    image_platform_pairs = set(image_per_service.values())
    log.debug(f"image_platform_pairs: {image_platform_pairs}")

    # Determine which images will be needed at `docker-compose up` time.
    images_selection = select_unique_images(
        image_platform_pairs, manifests_per_image, req_platforms=req_platforms)

    # At this point the pairs are (image, digest) are unique but let us make
    # sure the digests alone are also unique. If not, it means the same image is
    # being referenced in two different ways which the code in Aktualizr would
    # not handle correctly. Users can easily work around this corner case by
    # always referencing an image in the same way in their compose file.
    digests_unique = set()
    for _spec, sel_digest in images_selection:
        if sel_digest in digests_unique:
            raise TorizonCoreBuilderError(
                f"Image with digest {sel_digest} has been selected more than once"
                " through different names which is not supported.")
        digests_unique.add(sel_digest)

    # Build tarball with the images.
    docker_dir = os.path.join(images_dir, sha256 + ".images")
    os.mkdir(docker_dir)
    build_docker_tarballs(
        images_selection, docker_dir,
        host_workdir=get_host_workdir(),
        dind_params=dind_params, dind_env=dind_env)


def fetch_binary_target(target, repo_url, images_dir, *,
                        sha256=None, length=None,
                        access_token=None, name=None, version=None,
                        custom_uri=None):
    """Fetch a binary file target from the TUF repo

    For details on the parameters, see :func:`fetch_file_target`.
    """

    log.info(f"Fetching binary target '{target}'")
    fetch_file_target(target, repo_url, images_dir,
                      sha256=sha256, length=length, access_token=access_token,
                      name=name, version=version, custom_uri=custom_uri)


def fetch_imgrepo_metadata(repo_url, dest_dir, access_token=None, verbose=True):
    """Fetch all the required metadata from an Uptane image repo

    :param repo_url: Base URL of the TUF repository as it appears in the
                     credentials file.
    :param dest_dir: Destination directory of the metadata files.
    :param access_token: OAuth2 access token giving access to the TUF repo at
                         the OTA server.
    """

    # 1st: Fetch the snapshot metadata from where we learn about all
    # the other metadata files that should be fetched. With this approach
    # we will fetch more than the minimal needed but the advantage is that
    # we do not have to parse and understand the delegations.

    # NOTE: We do no validations in the snapshot metadata ATM (the device
    #       will do all required validations in the end).
    if verbose:
        log.info(f"Fetching '{SNAPSHOT_META_FILE}'")

    url = urljoin(repo_url + "/", f"api/v1/user_repo/{SNAPSHOT_META_FILE}")
    snapshot_meta = fetch_validate(
        url, SNAPSHOT_META_FILE, dest_dir,
        sha256=None, length=None, access_token=access_token, parse="json")

    # Fetch the various metadata files (except "root.json")
    known_metadata_files = [TARGETS_META_FILE]
    for fname, fmeta in snapshot_meta["signed"]["meta"].items():
        url = None
        if fname == ROOT_META_FILE:
            # The root.json file will be handled specially later.
            continue

        if fname in known_metadata_files:
            # Known metadata files are assumed to be at the root of the repo.
            url = urljoin(repo_url + "/", f"api/v1/user_repo/{fname}")

        else:
            # All the rest is assumed to be a delegation.
            # NOTE: Toradex delegation files start with 'tdx-', so we issue a
            #       warning here to help us know if the pattern changes; this
            #       should probably be removed in the future.
            if not fname.startswith("tdx-"):
                log.warning(f"Assuming file {fname} to be a delegation")
            url = urljoin(repo_url + "/", f"api/v1/user_repo/delegations/{fname}")
        if verbose:
            log.info(f"Fetching '{fname}'")
        # NOTE: The sha256 in the metadata does not match the actual files returned.
        # This is because the sha256 is calculated against the canonicalized JSON,
        # and the server does not return the JSON in canonicalized form.
        fetch_validate(
            url, fname, dest_dir,
            # sha256=fmeta["hashes"].get("sha256"),
            length=fmeta["length"],
            access_token=access_token)

    # Fetch the various versions of the "root.json" file in parallel:
    last_root_version = snapshot_meta["signed"]["meta"]["root.json"]["version"]
    downloads = []
    for version in range(1, last_root_version + 1):
        fname = f"{version}.root.json"
        url = urljoin(repo_url + "/", f"api/v1/user_repo/{fname}")
        downloads.append((url, fname))

    if verbose:
        log.info(f"Fetching {len(downloads)} root metadata file(s) in parallel")

    # It seems we cannot check the SHA and length of previous root data.
    total = len(downloads)
    with ThreadPoolExecutor(max_workers=PARALLEL_DOWNLOADS) as executor:
        futures = {
            executor.submit(fetch_validate, url, fname, dest_dir,
                            access_token=access_token): fname
            for url, fname in downloads
        }
        for count, future in enumerate(as_completed(futures), 1):
            future.result()
            if verbose:
                log.info(f"Fetched root metadata ({count} of {total})")


def fetch_director_metadata(lockbox_name, director_url, dest_dir, access_token=None):
    """Fetch (root) metadata from an Uptane director repo"""

    is_local_file = lockbox_name.endswith(JSON_EXT)
    if is_local_file:
        lockbox_file = lockbox_name
        lockbox_name = os.path.basename(lockbox_name[:-len(JSON_EXT)])
    else:
        lockbox_file = lockbox_name + JSON_EXT

    # Image name must not be reserved and must contain only characters that are
    # safe to store on the file system (there might be other constraints enforced
    # by the server as well).
    if lockbox_name.lower() in RESERVED_LOCKBOX_NAMES:
        raise TorizonCoreBuilderError(
            f"Error: Lockbox name '{lockbox_name}' is reserved and cannot be used (aborting)")

    if not all(ch not in UNSAFE_FILENAME_CHARS for ch in lockbox_name):
        raise TorizonCoreBuilderError(
            f"Error: Lockbox name '{lockbox_name}' contains disallowed characters (aborting)")

    # ---
    # Get offline targets and snapshot metadata files.
    # ---
    if is_local_file:
        # For the local case we simply copy the files to the destination.
        log.info(f"Copying {lockbox_file} -> {dest_dir}")
        shutil.copy(lockbox_file, dest_dir)

        snapshot_file = os.path.join(
            os.path.dirname(lockbox_file), OFFLINE_SNAPSHOT_FILE)
        log.info(f"Copying {snapshot_file} -> {dest_dir}")
        shutil.copy(snapshot_file, dest_dir)

    else:
        # Fetch the targets metadata for the specified offline-update.
        url = urljoin(director_url + "/", f"api/v1/admin/repo/offline-updates/{lockbox_file}")
        try:
            log.info(f"Fetching '{lockbox_file}'")
            fetch_validate(
                url, lockbox_file, dest_dir,
                sha256=None, length=None, access_token=access_token)

        except FetchError as exc:
            log.warning(str(exc))
            # pylint: disable-next=raise-missing-from
            raise TorizonCoreBuilderError(
                f"Error: Could not fetch Lockbox named '{lockbox_name}' from server")

        # Fetch the snapshot metadata for the specified offline-update.
        snapshot_file = OFFLINE_SNAPSHOT_FILE
        url = urljoin(director_url + "/", f"api/v1/admin/repo/{snapshot_file}")
        log.info(f"Fetching '{snapshot_file}'")
        fetch_validate(
            url, snapshot_file, dest_dir,
            sha256=None, length=None, access_token=access_token)

    # ---
    # Get all versions of root metadata.
    # ---
    # First fetch the root.json and then fetch all versions denoted in the latest root.json.
    # It is necessary to first fetch root.json (without a version) because the cloud will check
    # and ensure the director root metadata expires after all the offline-update roles.
    # If necessary, the cloud  will produce a new root.json version (expiring 6 months after the
    # last offline update) before responding to the GET request.
    #
    # Fetching root metadata with the version will skip this validation and could result in
    # root-metadata expiring before the offline metadata.

    url = urljoin(director_url + "/", f"api/v1/admin/repo/{ROOT_META_FILE}")
    try:
        log.info(f"Fetching {ROOT_META_FILE}")
        fetch_validate(
            url, ROOT_META_FILE, dest_dir,
            sha256=None, length=None, access_token=access_token)

    except FetchError as exc:
        log.warning(str(exc))
        # pylint: disable-next=raise-missing-from
        raise TorizonCoreBuilderError(
            f"Error: Could not fetch toplevel {ROOT_META_FILE} from server")

    top_level_root_file = os.path.join(dest_dir, ROOT_META_FILE)
    top_level_root = load_metadata(
        top_level_root_file, ftype="json", maxlen=DEFAULT_METADATA_MAXLEN)
    latest_root_version = top_level_root["parsed"]["signed"]["version"]

    downloads = []
    for version in range(1, latest_root_version + 1):
        fname = f"{version}.root.json"
        url = urljoin(director_url + "/", f"api/v1/admin/repo/{fname}")
        downloads.append((url, fname))

    log.info(f"Fetching {len(downloads)} director root metadata file(s) in parallel")

    total = len(downloads)
    with ThreadPoolExecutor(max_workers=PARALLEL_DOWNLOADS) as executor:
        futures = {
            executor.submit(fetch_validate, url, fname, dest_dir,
                            sha256=None, length=None,
                            access_token=access_token): fname
            for url, fname in downloads
        }
        for count, future in enumerate(as_completed(futures), 1):
            fname = futures[future]
            try:
                future.result()
            except FetchError as exc:
                log.warning(str(exc))
                # pylint: disable-next=raise-missing-from
                raise TorizonCoreBuilderError(
                    f"Error: Could not fetch metadata file '{fname}' from server")
            log.info(f"Fetched director root metadata ({count} of {total})")

def load_imgrepo_targets(source_dir, verbose=True):
    """Load Uptane lockbox image repo targets metadata (top-level and delegations)"""

    # Load top-level targets:
    targets_file = os.path.join(source_dir, TARGETS_META_FILE)
    if verbose:
        log.info(f"Loading image-repo targets metadata from '{targets_file}'")
    targets_metadata = load_metadata(
        targets_file, ftype="json", maxlen=TARGETS_METADATA_MAXLEN)
    assert targets_metadata["parsed"]["signed"]["_type"] == "Targets"

    # TODO: Test with data having multiple levels of delegations.
    # Helper for parsing delegations (depth-first recursion).
    n_loaded = 0

    def _load_delegations(node, verbose=True):
        nonlocal n_loaded
        children = {}
        for deleg in node["parsed"]["signed"]["delegations"]["roles"]:
            deleg_name = deleg["name"]
            deleg_file = os.path.join(source_dir, deleg_name + JSON_EXT)
            if verbose:
                log.info(f"Loading image-repo delegated targets metadata from '{deleg_file}'")
            deleg_metadata = load_metadata(
                deleg_file, ftype="json", maxlen=TARGETS_METADATA_MAXLEN)
            assert deleg_metadata["parsed"]["signed"]["_type"] == "Targets"
            children[deleg_name] = deleg_metadata
            # Recursion:
            if "delegations" in deleg_metadata["parsed"]["signed"]:
                _load_delegations(deleg_metadata, verbose)
            # Limit total number of delegations files loaded (protect from loops in metadata).
            n_loaded += 1
            assert n_loaded < 32, "Too many delegation files"
        # 'children' is a dict: (role name, result of load_metadata())
        node["children"] = children

    if "delegations" in targets_metadata["parsed"]["signed"]:
        _load_delegations(targets_metadata, verbose)

    # print(json.dumps(targets_metadata, indent=4))
    return targets_metadata


def find_imgrepo_target(targets_metadata, sha256, name=None, length=None):
    """Find an Uptane target on the lockbox image repo metadata

    targets_metadata: metadata as loaded by load_imgrepo_targets()
    sha256: hash of the target to be found
    name: name of the target to be found (optional)
    length: length of the target to be found (optional)
    """

    # Use length parameter (TODO).

    for tgt_key, tgt_val in targets_metadata["parsed"]["signed"]["targets"].items():
        # Check criteria:
        if tgt_val["hashes"]["sha256"] != sha256:
            continue
        if name is not None and tgt_key != name:
            log.warning(f"Target {sha256} found by hash but name does not match "
                        f"({name} != {tgt_key})")
            continue
        if length is not None and length != tgt_val["length"]:
            log.warning(f"Target {sha256} found by hash but length does not match "
                        f"({length} != {tgt_val['length']})")
            continue
        # All conditions passed:
        return tgt_key, tgt_val

    def _find_in_delegations(node):
        for deleg in node["parsed"]["signed"]["delegations"]["roles"]:
            deleg_name = deleg["name"]
            deleg_paths = deleg.get("paths", [])
            if name is not None and not any(fnmatchcase(name, wcd) for wcd in deleg_paths):
                log.debug(f"Name {name} does not match any of {deleg_paths}")
                continue

            deleg_metadata = node["children"][deleg_name]
            for tgt_key, tgt_val in deleg_metadata["parsed"]["signed"]["targets"].items():
                # Check criteria:
                if tgt_val["hashes"]["sha256"] != sha256:
                    continue
                if name is not None and tgt_key != name:
                    log.warning(f"Target {sha256} found by hash but name does not match "
                                f"({name} != {tgt_key})")
                    continue
                if length is not None and length != tgt_val["length"]:
                    log.warning(f"Target {sha256} found by hash but length does not match "
                                f"({length} != {tgt_val['length']})")
                    continue
                # All conditions passed:
                return tgt_key, tgt_val

            # Recursion:
            if "delegations" in deleg_metadata["parsed"]["signed"]:
                tgt_key, tgt_val = _find_in_delegations(deleg_metadata)
                if tgt_key is not None:
                    return tgt_key, tgt_val
        return None, None

    # Not found at top-level - search in delegations:
    if "delegations" in targets_metadata["parsed"]["signed"]:
        return _find_in_delegations(targets_metadata)

    return None, None


def run_uptane_command(command, verbose):
    """Run a single command using uptane-sign/uptane-push"""
    if verbose:
        command.append("--verbose")
    uptane_command = subprocess.run(command, check=False, capture_output=True)

    stdoutstr = uptane_command.stdout.decode().strip()
    if verbose:
        if len(stdoutstr) > 0:
            print("== uptane-sign stdout:")
            log.debug(stdoutstr)

    # Show warnings to user by default.
    stderrstr = uptane_command.stderr.decode()
    if len(stderrstr) > 0:
        print("== uptane-sign stderr:")
        log.warning(stderrstr)

    if uptane_command.returncode != 0:
        if not verbose:
            log.error(stdoutstr)
        raise TorizonCoreBuilderError(
            f'Error ({str(uptane_command.returncode)}) running uptane command '
            f'"{command[0]}" with arguments "{command[1:]}"')


# pylint: disable-next=too-many-locals
def push_ref(ostree_dir, credentials, ref, *,
             package_name=None, package_version=None,
             hardwareids=None, description=None, verbose=False):
    """Push OSTree reference to OTA server.

    Push given reference of a given archive OSTree repository to the OTA server
    referenced by the credentials.zip file.
    """

    repo = ostree.open_ostree(ostree_dir)
    commit = repo.read_commit(ref).out_commit

    metadata, subject, body = ostree.get_metadata_from_checksum(repo, commit)
    package_name = package_name or ref
    package_version = package_version or subject

    # Try to find hardware id to use from OSTree metadata
    module = None
    if "oe.sota-hardware-id" in metadata:
        module = metadata["oe.sota-hardware-id"]
    elif "oe.machine" in metadata:
        module = metadata["oe.machine"]

    if hardwareids is not None:
        if module not in hardwareids:
            log.info(
                f"The default hardware id '{module}' is being overridden. "
                "If you want to keep it, re-run the command adding the "
                f"flag --hardwareid '{module}'.")
        module = ",".join(hardwareids)

    if module is None:
        raise TorizonCoreBuilderError(
            "No hardware id found in OSTree metadata and none provided.")

    garage_push = ["garage-push",
                   "--credentials", credentials,
                   "--repo", ostree_dir,
                   "--ref", commit]

    # Extend target info with OSTree commit metadata
    # Remove some metadata keys which are already used otherwise or ar rather
    # large and blow up targets.json unnecessary
    for key in ["oe.garage-target-name", "oe.garage-target-version", "oe.sota-hardware-id",
                "oe.layers", "oe.kargs-default"]:
        metadata.pop(key, None)

    custom_metadata = {
        "commitSubject": subject,
        "commitBody": body,
        "ostreeMetadata": metadata
    }

    if not verbose:
        garage_push.extend(["--loglevel", "4"])
    log.info(f"Pushing {ref} (commit checksum {commit}) to OTA server.")
    run_uptane_command(garage_push, verbose)

    log.info(f"Pushed {ref} successfully.")

    log.info(f"Signing OSTree package {package_name} (commit checksum {commit}) "
             f"for Hardware Id(s) \"{module}\".")

    run_uptane_command(["uptane-sign", "init",
                        "--credentials", credentials,
                        "--repo", TUF_REPO_DIR], verbose)

    run_uptane_command(["uptane-sign", "targets", "pull",
                        "--repo", TUF_REPO_DIR], verbose)

    run_uptane_command(["uptane-sign", "targets", "add",
                        "--repo", TUF_REPO_DIR,
                        "--name", package_name,
                        "--format", "OSTREE",
                        "--version", package_version,
                        "--length", "0",
                        "--sha256", commit,
                        "--hardwareids", module,
                        "--customMeta", json.dumps(custom_metadata)], verbose)

    run_uptane_command(["uptane-sign", "targets", "sign",
                        "--repo", TUF_REPO_DIR,
                        "--key-name", "targets"], verbose)

    run_uptane_command(["uptane-sign", "targets", "push",
                        "--repo", TUF_REPO_DIR], verbose)

    log.info(f"Signed and pushed OSTree package {package_name} successfully.")

    if description is not None:
        update_description(description, package_name, package_version, credentials)


def validate_package_selection_criteria(criteria):
    """Validate the search criterion and search term
    :param criteria: List of dicts with a search criterion as the key
                     and the search term as the value. (e.g. {<criterion>: <term>}).
    """
    valid_criterion_keys = ["sha256"]
    for criterion in criteria:
        for key, value in criterion.items():
            if key not in valid_criterion_keys:
                raise InvalidDataError(
                    "Error: Invalid Criterion, please select a supported criterion: "
                    f"{valid_criterion_keys}")

            if key == "sha256" and not HASH_REGEX.match(value):
                raise InvalidDataError(
                    f"Invalid SHA256 specified: '{', '.join(value)}'; The complete "
                    "SHA256 should have 64 lowercase hexadecimal characters.")


def translate_compatible_packages(credentials, criteria):
    """Find the target packages using the search criterion and the search term. The
    found packages are translated into the 'compatibleWith' information required by
    the package.

    :param credentials: Name of the `credentials.zip` file.
    :param criteria: List of dicts with a search criterion as the key
                     and the search term as the value. (e.g. {<criterion>: <term>}).
    :return: Found packages' information and the 'compatibleWith' value.
    """

    package_info = []
    compatible_with = []

    if not criteria:
        return package_info, compatible_with

    server_creds = sotaops.ServerCredentials(credentials)
    token = sotaops.get_access_token(server_creds)

    with TemporaryDirectory() as tmpdir:
        fetch_imgrepo_metadata(server_creds.repo_url, tmpdir, token, verbose=False)
        targets_metadata = load_imgrepo_targets(tmpdir, verbose=False)

    for criterion in criteria:
        target_hash = criterion.get("sha256")
        _, metadata_value = find_imgrepo_target(targets_metadata, target_hash)

        if metadata_value is None:
            raise InvalidDataError(
                f"Error: Unable to find any packages with the 'sha256={target_hash}'")

        package_name = None
        package_version = None

        if metadata_value.get("custom"):
            package_name = metadata_value["custom"].get("name")
            package_version = metadata_value["custom"].get("commitSubject")

        package_info.append({
            "name": package_name,
            "version": package_version})

        compatible_with.append({"sha256": target_hash})

    return package_info, compatible_with


def push_compose(credentials, target, version, compose_file, *,
                 canonicalize=None, force=False, description=None,
                 compatible_with=None, verbose=False):
    """Push docker-compose file to OTA server."""

    if not compose_file.endswith('.yml') and not compose_file.endswith('.yaml'):
        raise TorizonCoreBuilderError(
            f"File '{compose_file}' does not seem like a Docker compose file. "
            "It does not end with '.yml' or '.yaml'.")

    is_lockfile = bool(re.match(r".+\.lock\.ya?ml$", os.path.basename(compose_file)))
    is_canonical = False

    # Only check if the file is already in a canonical form if the input is a lock
    # file or if the canonicalize parameter was not passed.
    if not canonicalize or is_lockfile:
        is_canonical = is_canonicalized(compose_file)

    # The lock file must be in its canonical form
    if not is_canonical and is_lockfile:
        raise TorizonCoreBuilderError(
            f"Error: '{compose_file}' is not in canonical form, which is expected "
            "for files with the '.lock' extension.")

    if canonicalize and not is_lockfile:
        push_file = canonicalize_compose_file(compose_file, force)
        is_canonical = True
    else:
        push_file = compose_file

    if target is None:
        target = os.path.basename(push_file)

    if not is_canonical:
        log.info("Warning: This package is not in its canonical form. Canonical "
                 "form is required with offline updates (see help for details); "
                 "future versions of the tool will canonicalize the file by "
                 "default as this is considered a good practice.")

    custom_metadata = {}

    custom_metadata["canonical_compose_file"] = is_canonical

    if compatible_with:
        custom_metadata["compatibleWith"] = compatible_with

    log.info(f"You should keep '{os.path.basename(push_file)}' under your "
             "version control system.")

    uptane_sign_push(credentials=credentials,
                     push_file=push_file,
                     target=target,
                     version=version,
                     hardwareids_str="docker-compose",
                     custom_metadata=custom_metadata,
                     verbose=verbose)

    if description is not None:
        update_description(description, target, version, credentials)


def push_generic(credentials, target, version, generic_file, *,
                 custom_meta, hardwareids, description=None,
                 compatible_with=None, verbose=False):
    """Push Generic package file to OTA server."""

    assert hardwareids, "'hardwareids' must be a non-empty list"

    if target is None:
        target = generic_file

    hardwareids_str = ' '.join(hardwareids)

    if custom_meta:
        custom_meta = json.loads(custom_meta)
    else:
        custom_meta = {}

    if compatible_with:
        custom_meta["compatibleWith"] = compatible_with

    uptane_sign_push(credentials=credentials,
                     push_file=generic_file,
                     target=target,
                     version=version,
                     hardwareids_str=hardwareids_str,
                     custom_metadata=custom_meta,
                     verbose=verbose)

    if description is not None:
        update_description(description, target, version, credentials)


def update_description(description, target, version, credentials):
    """Update Package Description"""
    server_creds = sotaops.ServerCredentials(credentials)
    token = sotaops.get_access_token(server_creds)

    put = requests.put(
        f"{server_creds.repo_url}/api/v1/user_repo/comments/{target}-{version}",
        data=json.dumps({"comment": f"{description}"}),
        headers={"Authorization": f"Bearer {token}",
                 "Content-Type": "application/json"},
        timeout=(DEFAULT_CONNECT_TIMEOUT, UPDATE_DESC_TIMEOUT))

    if put.status_code == requests.codes["ok"]:
        log.info(f"Description for {target} updated.")
    else:
        log.error(f"Could not update description for {target}.")
        log.error(put.text)


def upload_static_delta_parts(delta_dir, ostree_url, delta_id, headers):
    """
    Upload static delta parts to treehub.

    :param delta_dir: A path to static delta parts.
    :param ostree_url: OStree server url.
    :param delta_id: Computed static delta identifier.
    :param headers: http headers.
    """

    log.info("Uploading static delta parts to treehub...")
    for item in os.listdir(delta_dir):
        if not re.match(r'\d+', item):
            continue

        with open(f"{delta_dir}/{item}", "rb") as file_contents:
            post = run_with_loading_animation(
                func=requests.post,
                args=(f"{ostree_url}/deltas/{delta_id}/{item}", file_contents),
                kwargs={'headers': headers},
                loading_msg="Uploading part...",
                end_msg="")

            if post.status_code == requests.codes["ok"]:
                log.info(f"Static delta part {item} uploaded.")
            else:
                log.error(post.text)
                raise TorizonCoreBuilderError(f"Error uploading static delta part {item}")


def upload_static_delta_superblock(delta_dir, ostree_url, delta_id, headers):
    """
    Upload static delta superblock to treehub.

    :param ostree_url: OStree server url.
    :param delta_id: Computed static delta identifier.
    :param delta_dir: A path to static delta parts.
    :param headers: http headers.
    """
    with open(f"{delta_dir}/superblock", "rb") as file_contents:
        post = requests.post(
            f"{ostree_url}/deltas/{delta_id}/superblock",
            data=file_contents, headers=headers,
            timeout=(DEFAULT_CONNECT_TIMEOUT, UPLOAD_DELTA_TIMEOUT))
        if post.status_code == requests.codes["ok"]:
            log.info("Static delta superblock uploaded.")
        else:
            log.error(post.text)
            raise TorizonCoreBuilderError("Error uploading static delta superblock")


def set_images_hash(compose_file_data):
    """
    Set hash for the images defined in the Docker compose file.

    :param compose_file_data: The Docker compose file data.
    """

    validate_compose_file(compose_file_data)

    for svc_spec in compose_file_data['services'].values():
        image_name = svc_spec.get('image')
        image_parsed = parse_image_name(image_name)
        log.debug(f"Parsed {image_name} into {image_parsed}.")
        if image_parsed.uses_digest():
            # Normalize the name (handle the case where tag+digest is passed)
            svc_spec['image'] = image_parsed.get_name_with_tag()
            continue
        registry = RegistryOperations(image_parsed.registry)
        response, image_digest = registry.get_manifest(
            image_parsed.get_name_with_tag(), ret_digest=True)
        assert response.status_code == requests.codes["ok"]

        # Replace tag by digest:
        image_parsed.set_tag(image_digest, is_digest=True)
        svc_spec['image'] = image_parsed.get_name_with_tag()


def canonicalize_compose_file(compose_file, force=False):
    """
    Canonicalize a Docker compose file that could be pushed to OTA and
    saved as a '.lock.yml/yaml' file.

    :param compose_file: The Docker compose file.
    :param force: Force the overwriting of the canonicalized file.
    :returns:
        The canonicalized data of the Docker compose file as well as the
        name of the '.lock' file created.
    """

    if not compose_file.endswith('.yml') and not compose_file.endswith('.yaml'):
        raise TorizonCoreBuilderError(
            f"File '{compose_file}' does not seem like a Docker compose file. "
            "It does not end with '.yml' or '.yaml'.")

    is_canonical, compose_file_data = is_canonicalized(compose_file, True)

    if is_canonical:
        log.info(f"File '{compose_file}' is already in canonical form.")
        return compose_file

    canonical_compose_file_lock = re.sub(r"(.ya?ml)$", r".lock\1", compose_file)
    if os.path.exists(canonical_compose_file_lock) and not force:
        raise TorizonCoreBuilderError(
            f"Canonicalized file '{canonical_compose_file_lock}' already exists. "
            "Please use the '--force' parameter if you want it to be overwritten.")

    set_images_hash(compose_file_data)
    canonical_data = yaml.safe_dump(compose_file_data)

    with open(canonical_compose_file_lock, 'w', encoding='utf-8') as compose_lock_fd:
        compose_lock_fd.write(canonical_data)
    set_output_ownership(canonical_compose_file_lock)
    log.info(f"Canonicalized file '{canonical_compose_file_lock}' has been generated.")

    return canonical_compose_file_lock


def is_canonicalized(compose_file, ret_parsed=False):
    """
    Check if a docker-compose file is canonicalized.

    :param compose_file: The Docker Compose file to be checked.
    :param ret_parsed: Add the parsed object to the return.
    :returns:
        Whether or not the input is canonicalized.
        If the 'ret_parsed' argument is set to True, the parsed version
        of the docker compose file will be added to the return.
    """
    def images_with_digest(data):
        services = data.get('services', {})
        _uses_digest = []
        for service in services.values():
            if service.get('image'):
                _uses_digest.append(parse_image_name(service.get('image')).uses_digest())
        return all(_uses_digest)

    with open(compose_file, encoding='utf-8') as file:
        compose_file_data = yaml.safe_load(file)
        file.seek(0)
        original_yaml_string = file.read()

    is_canonical = False
    # Checking for correct file structure and adherence to image references with digests
    validate_compose_file(compose_file_data)
    if images_with_digest(compose_file_data):
        is_canonical = original_yaml_string == yaml.safe_dump(compose_file_data)

    return (is_canonical, compose_file_data) if ret_parsed else is_canonical


def get_shared_provdata(dest_file, repo_url, director_url, access_token=None):
    """Get shared provisioning data from OTA server."""

    def restrict_perms(dirname):
        for fname in os.listdir(dirname):
            fullfname = os.path.join(dirname, fname)
            assert os.path.isfile(fullfname)
            os.chmod(fullfname, 0o644)
            os.chown(fullfname, uid=0, gid=0)

    with TemporaryDirectory() as tmpdir:
        toplvl_entries = []

        # Create destination subdir for image repo metadata.
        image_root_dir = os.path.join(tmpdir, PROV_IMGREPO_DIRNAME)
        os.mkdir(image_root_dir, 0o511)

        # Fetch root metadata of image repo.
        image_root_fname = ROOT_META_FILE
        image_root_url = urljoin(repo_url + "/", f"api/v1/user_repo/{image_root_fname}")
        log.info(f"Fetching '{image_root_fname}' from image repository.")
        fetch_validate(image_root_url, image_root_fname, image_root_dir,
                       access_token=access_token)
        restrict_perms(image_root_dir)
        toplvl_entries.append(PROV_IMGREPO_DIRNAME)

        # Create destination subdir for director repo metadata.
        direc_root_dir = os.path.join(tmpdir, PROV_DIRECTOR_DIRNAME)
        os.mkdir(direc_root_dir, 0o511)

        # Fetch root metadata of director repo.
        direc_root_fname = ROOT_META_FILE
        direc_root_url = urljoin(director_url + "/", f"api/v1/admin/repo/{direc_root_fname}")
        log.info(f"Fetching '{direc_root_fname}' from director repository.")
        fetch_validate(direc_root_url, direc_root_fname, direc_root_dir,
                       access_token=access_token)
        restrict_perms(direc_root_dir)
        toplvl_entries.append(PROV_DIRECTOR_DIRNAME)

        # Create final tarball:
        assert dest_file.endswith(".tar.gz")
        subprocess.check_output(
            ["tar", "--numeric-owner", "--preserve-permissions",
             "-czvf", os.path.abspath(dest_file),
             "-C", tmpdir, *toplvl_entries])

        set_output_ownership(dest_file)
        log.info(f"Shared data archive '{dest_file}' successfully generated.")


# pylint: disable-next=too-many-locals
def push_fuse(credentials, target, version, fuse_file, hardwareids, *,
              compatible_with=None, force=False, description=None, verbose=False):
    """Push fuse package file to OTA server."""


    validate_fuse_file(fuse_file, hardwareids)

    is_lockfile = bool(re.match(r".+\.lock\.ya?ml$", os.path.basename(fuse_file)))
    is_canonical = False

    # Only check if the file is already in a canonical form if the input
    # appears to be a lock file by name.
    if is_lockfile:
        is_canonical = is_fuse_canonicalized(fuse_file, False)

    # The lock file must be in its canonical form
    if not is_canonical and is_lockfile:
        raise TorizonCoreBuilderError(
            f"Error: '{fuse_file}' is not in canonical form, which is expected "
            "for files with the '.lock' extension.")

    if not is_lockfile:
        push_file = canonicalize_fuse_file(fuse_file, force)
        is_canonical = True
    else:
        log.debug(f"Input file '{fuse_file}' is already in canonical form, "
                  "proceeding.")
        push_file = fuse_file

    hardwareids_str = ' '.join(hardwareids)
    if target is None:
        target = os.path.basename(push_file)

    # TODO: Do we need a custom metadata flag for canonical here?
    custom_metadata = {}
    if compatible_with:
        custom_metadata["compatibleWith"] = compatible_with

    uptane_sign_push(credentials=credentials,
                     push_file=push_file,
                     target=target,
                     version=version,
                     hardwareids_str=hardwareids_str,
                     custom_metadata=custom_metadata,
                     verbose=verbose)

    if description is not None:
        update_description(description, target, version, credentials)


def fuse_count_for_tech(tech):
    """Determine the number of fuses based on the secure-boot technology

    :param tech: The secure-boot technology being used.
    :returns: An int with the number of fuses
    """

    if tech == "hab":
        fuse_num = 8
    elif tech == "ahab":
        fuse_num = 16
    else:
        assert False, f"Unhandled Secure Boot technology '{tech}'."

    return fuse_num


def fuse_hwid_to_machine(hwid):
    """Translate a fuse hwid to a machine name."""
    if not hwid.endswith(FUSE_HWID_SUFFIX):
        return None
    return hwid[:-len(FUSE_HWID_SUFFIX)]


def validate_fuse_file(fuse_file, hardwareids):
    """
    Validate the provided fuse yaml file

    :param fuse_file: Path to fuse yaml file
    :param hardwareids: Hardware IDs that were provided by user
    :returns: The yaml data that was validated
    """

    # Determine the Secure Boot technologies involved:
    secboot_techs = set()
    for hwid in hardwareids:
        _mach = fuse_hwid_to_machine(hwid)
        _tech = SECBOOT_TECH_PER_MACHINE.get(_mach)
        if not _tech:
            raise TorizonCoreBuilderError(
                f"Cannot determine the fuse technology used by machine {_mach}.")
        secboot_techs.add(_tech)

    log.debug("Secure Boot technologies associated with the passed hardware IDs: '%s'",
              str(secboot_techs))

    if len(secboot_techs) > 1:
        raise TorizonCoreBuilderError(
            f"Provided hardware ids: {hardwareids} are associated with different"
            " Secure Boot technologies which is not possible in one fuse type package.")

    fuse_num = fuse_count_for_tech(next(iter(secboot_techs)))

    # Next check overall layout against schema
    parsed_file = parse_config_file(fuse_file, schema_path=FUSE_SCHEMA_FILE)

    # Finally check if the number of fuse values is expected for the A/HAB type
    parsed_keys = list(parsed_file['fuses'].keys())
    parsed_keys.remove("fuse-close")
    parsed_fuse_num = len(parsed_keys)
    if parsed_fuse_num != fuse_num:
        raise TorizonCoreBuilderError(
            f"Found {parsed_fuse_num} fuse values in provided yaml file, "
            f"but expected to find {fuse_num} instead.")

    return parsed_file


def canonicalize_fuse_file(fuse_file, force=False):
    """
    Canonicalize a fuse package yaml file that could be pushed to OTA and
    saved as a '.lock.yml/yaml' file.

    :param fuse_file: The fuse package file.
    :param force: Force the overwriting of the canonicalized file.
    :returns:
        The canonicalized data of the fuse yaml file as well as the
        name of the '.lock' file created.
    """

    if not fuse_file.endswith('.yml') and not fuse_file.endswith('.yaml'):
        raise TorizonCoreBuilderError(
            f"File '{fuse_file}' does not seem like a yaml file. "
            "It does not end with '.yml' or '.yaml'.")

    is_canonical, fuse_file_data = is_fuse_canonicalized(fuse_file, True)

    if is_canonical:
        log.info(f"File '{fuse_file}' is already in canonical form.")
        return fuse_file

    canonical_fuse_file_lock = re.sub(r"(.ya?ml)$", r".lock\1", fuse_file)
    if os.path.exists(canonical_fuse_file_lock) and not force:
        raise TorizonCoreBuilderError(
            f"Canonicalized file '{canonical_fuse_file_lock}' already exists. "
            "Please use the '--force' parameter if you want it to be overwritten.")

    with open(canonical_fuse_file_lock, 'w', encoding='utf-8') as fuse_lock_fd:
        fuse_lock_fd.write(fuse_file_data)
    set_output_ownership(canonical_fuse_file_lock)
    log.info(f"Canonicalized file '{canonical_fuse_file_lock}' has been generated.")

    return canonical_fuse_file_lock


def is_fuse_canonicalized(fuse_file, ret_parsed=False):
    """
    Check if a fuse package yaml file is canonicalized.

    :param fuse_file: The fuse package file to be checked.
    :param ret_parsed: Add the parsed object to the return.
    :returns:
        Whether or not the input is canonicalized.
        If the 'ret_parsed' argument is set to True, the parsed version
        of the fuse file will be added to the return.
    """
    with open(fuse_file, encoding='utf-8') as file:
        fuse_file_data = yaml.safe_load(file)
        file.seek(0)
        original_yaml_string = file.read()

    is_canonical = False

    # yaml.safe_load transforms hexadecimal to decimal, restore the original hex
    restore_hex(fuse_file_data)
    # Lowercase everything for fuse package only
    # Also remove the single quotes added by pyyaml on the restored hex values
    canonical_data = yaml.safe_dump(fuse_file_data).lower().replace("'", "")
    is_canonical = original_yaml_string == canonical_data

    return (is_canonical, canonical_data) if ret_parsed else is_canonical


def restore_hex(yaml_file_data):
    """
    Restore hexadecimal values in fuse package that were turned into decimal
    by pyyaml.

    :param yaml_file_data: The fuse package file data
    """

    for fuse_val in yaml_file_data['fuses'].keys():
        if "fuse-val" in fuse_val:
            dec_num = yaml_file_data['fuses'].get(fuse_val)
            hex_num = hex(dec_num)
            yaml_file_data['fuses'][fuse_val] = hex_num


def uptane_sign_push(*, credentials, push_file, target, version,
                     hardwareids_str, custom_metadata, verbose):
    """
    Use Uptane sign to push a file-based package to the OTA server

    :param credentials: The credentials file corresponding to the OTA
                        server that will be pushed to.
    :param push_file: The file-based package payload
    :param target: The name of the package
    :param version: The version of the package
    :param hardwareids_str: A string of hardware-ids
    :param custom_metadata: Custom metadata to be pushed with package
    :param verbose: Whether uptane-sign will execute with verbose output
    """

    log.info(f"Pushing '{os.path.basename(push_file)}' with package version "
             f"{version} to OTA server.")

    run_uptane_command(["uptane-sign", "init",
                        "--credentials", credentials,
                        "--repo", TUF_REPO_DIR], verbose)

    run_uptane_command(["uptane-sign", "targets", "pull",
                        "--repo", TUF_REPO_DIR], verbose)

    run_uptane_command(["uptane-sign", "targets", "upload",
                        "--repo", TUF_REPO_DIR,
                        "--input", push_file,
                        "--name", target,
                        "--version", version,
                        "--timeout", UPTANE_SIGN_UPLOAD_TIMEOUT], verbose)

    run_uptane_command(["uptane-sign", "targets", "add-uploaded",
                        "--repo", TUF_REPO_DIR,
                        "--input", push_file,
                        "--name", target,
                        "--version", version,
                        "--hardwareids", hardwareids_str,
                        "--customMeta", json.dumps(custom_metadata)], verbose)

    run_uptane_command(["uptane-sign", "targets", "sign",
                        "--repo", TUF_REPO_DIR,
                        "--key-name", "targets"], verbose)

    run_uptane_command(["uptane-sign", "targets", "push",
                        "--repo", TUF_REPO_DIR], verbose)

    log.info(f"Successfully pushed {os.path.basename(push_file)} to OTA server.")


def bootloader_hwid_to_machine(hwid):
    """Translate a bootloader hwid to a machine name."""
    if not hwid.endswith(BOOTLOADER_HWID_SUFFIX):
        return None
    return hwid[:-len(BOOTLOADER_HWID_SUFFIX)]


def _get_dd_options(hardwareids):
    """Get the dd options for the given (set of) hardware IDs."""
    dd_options = None
    for _hwid in hardwareids:
        _mach = bootloader_hwid_to_machine(_hwid)
        if _mach in BOOTLOADER_DD_OPTIONS_PER_MACHINE:
            assert dd_options is None, \
                "More than one valid hardware ID has been passed."
            dd_options = BOOTLOADER_DD_OPTIONS_PER_MACHINE[_mach]
            break
    assert dd_options is not None, "Exactly one valid hardware ID should be passed."
    return dd_options


# pylint: disable-next=too-many-arguments
def push_bootloader(*, credentials, target, version, boot_bin, json_file,
                    keep_vars, set_vars, reset, hardwareids, description,
                    verbose):
    """
    Push bootloader binary to OTA server

    :param credentials: Credentials file corresponding to the OTA server that
                        will be pushed to
    :param target: The name of the package
    :param version: The version of the package
    :param boot_bin: The bootloader binary file that will be pushed
    :param json_file: The json file containing metadata information about the
                      bootloader binary
    :param keep_vars: List of U-boot variables to keep during an update with
                      this package
    :param set_vars: Key-value list of U-boot variables to set during an update
                     with this package
    :param reset: Boolean switch on whether the U-Boot environment should be
                  reset during an update with this package
    :param hardwareids: List of hardwareids to associate this package with
    :param description: Package description
    :param verbose: Boolean switch on whether to print additional logs
    """

    assert hardwareids, "'hardwareids' must be not empty"

    # Define the "dd" options to be used; the CLI layer should ensure exactly one
    # known/valid hardware ID is passed but we double check this here.
    dd_options = _get_dd_options(hardwareids)
    custom_meta = create_bootloader_meta(json_file, keep_vars, set_vars, reset, dd_options)
    hardwareids_str = ' '.join(hardwareids)

    if target is None:
        target = os.path.basename(boot_bin)

    uptane_sign_push(credentials=credentials,
                     push_file=boot_bin,
                     target=target,
                     version=version,
                     hardwareids_str=hardwareids_str,
                     custom_metadata=custom_meta,
                     verbose=verbose)

    if description is not None:
        update_description(description, target, version, credentials)


# pylint: disable-next=too-many-locals
def create_bootloader_meta(json_file, keep_vars, set_vars, reset, dd_options):
    """
    Create the required custom metadata for a bootloader package

    :param json_file: The json file containing metadata information about
                      the bootloader
    :param keep_vars: List of U-boot variables to keep
    :param set_vars: Key-value list of U-Boot variables to set
    :param reset: Whether to reset U-Boot environment during update or not
    :param dd_options: Value to pass into the "ddOptions" metadata field
    """

    metadata = {
        "bootloader": {
            "ddOptions": "options",
            "dtVersion": "version",
            "env": {
                "type": "embedded",
                "resetOnUpdate": True,
                "embeddedOffset": 1234,
                "embeddedSize": 5678,
                "keepVars": None,
                "setVars": None
            }
        }
    }

    # Check if json_file is valid
    with open(json_file, "r", encoding="utf-8") as file:
        try:
            data = json.load(file)
        except:
            # pylint: disable-next=raise-missing-from
            raise ParseError(f"File \"{json_file}\" is not valid Json; aborting.")

    schema_path = os.path.join(os.path.dirname(__file__), UBOOT_JSON_SCHEMA_FILE)
    with open(schema_path, "r", encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    validate = jsonschema.Draft7Validator(schema)
    errors = []
    for error in validate.iter_errors(data):
        error_exc = ParseError(error.message)
        error_exc.set_source(file=json_file, prop=error.path)
        errors.append(error_exc)
    if errors:
        raise ParseErrors(f"Errors found in \"{json_file}\"; aborting.", payload=errors)

    # Get set_vars in the right format
    if set_vars:
        set_vars_dict = {}
        for pair in set_vars:
            key_value = pair.split('=', maxsplit=1)
            set_vars_dict[key_value[0].strip()] = key_value[1].strip()
    else:
        set_vars_dict = None

    # Populate final metadata
    if dd_options:
        metadata['bootloader']['ddOptions'] = dd_options
    metadata['bootloader']['dtVersion'] = data['ubootrelease']
    metadata['bootloader']['env']['resetOnUpdate'] = reset
    metadata['bootloader']['env']['embeddedOffset'] = data['envoffset']
    metadata['bootloader']['env']['embeddedSize'] = data['envsize']
    metadata['bootloader']['env']['keepVars'] = keep_vars or None
    metadata['bootloader']['env']['setVars'] = set_vars_dict or None

    log.debug(f"Bootloader metadata:\n{json.dumps(metadata, indent=2)}")

    return metadata
