"""Batch CLI frontend

Allows to bundle multiple images with containers in a single batch operation.
"""
import json
import logging
import os
import subprocess
import urllib

from tcbuilder.backend import common
from tcbuilder.errors import InvalidArgumentError, OperationFailureError
from tezi import downloader


TEZI_FEED_URL = "https://tezi.int.toradex.com:8443/tezifeed"

def get_images(artifactory_repo, branch, release_type, matrix_build_number, machine,
               distro, image):
    """Get list of Toradex Easy Installer images from feed URL"""

    filter_params = {'repo': artifactory_repo,
                     'BUILD_MANIFEST_BRANCH': branch,
                     'BUILD_PIPELINETYPE': release_type,
                     'BUILD_MACHINE': machine,
                     'BUILD_DISTRO': distro,
                     'BUILD_RECIPE': image}

    if matrix_build_number is not None:
        filter_params['MATRIX_BUILD_NUMBER'] = matrix_build_number

    params = urllib.parse.urlencode(filter_params)

    feed_url = "{}?{}".format(TEZI_FEED_URL, params)
    logging.info(f"Requestion from \"{feed_url}\"")
    req = urllib.request.urlopen(feed_url)
    content = req.read().decode(req.headers.get_content_charset() or "utf-8")

    # This gets the actual location of the images also considering HTTP 301/302
    # redirects...
    image_base_url = os.path.dirname(req.url)

    imagelist = json.loads(content)
    for _image in imagelist['images']:
        if not bool(urllib.parse.urlparse(_image).netloc):
            yield os.path.join(image_base_url, _image)
        else:
            yield _image


def do_batch(args):
    """Run "batch" sub-command"""

    output_dir_containers = os.path.abspath(args.bundle_directory)
    additional_size = common.get_additional_size(output_dir_containers, common.DOCKER_FILES_TO_ADD)
    if additional_size is None:
        raise InvalidArgumentError("Docker Container bundle missing, use bundle sub-command.")

    image_dir = os.path.abspath(args.output_directory)

    if not os.path.exists(image_dir):
        os.mkdir(image_dir)

    for machine in args.machines:
        for distro in args.distro:
            # Get TorizonCore Toradex Easy Installer images for
            # machine/distro/image combination...
            image_urls = list(get_images(args.repo, args.branch,
                                         args.release_type, args.matrix_build_number,
                                         machine, distro, 'torizon-core-docker'))

            if len(image_urls) == 0:
                continue

            # Create image dir for image and add containers there...
            output_dir = os.path.join(image_dir, machine, distro, args.image_directory)
            os.makedirs(output_dir, exist_ok=True)

            for url in image_urls:
                logging.info(f"Downloading from {url}")
                downloader.download(url, output_dir)

            version = common.combine_single_image(output_dir_containers, common.DOCKER_FILES_TO_ADD,
                                                  additional_size, output_dir, args.image_name,
                                                  args.image_description, args.licence_file,
                                                  args.release_notes_file)

            # Start Artifactory upload with a empty environment
            if args.post_script is not None:
                logging.info(f"Executing post image generation script {args.post_script}.")

                cp_process = subprocess.run([args.post_script, machine, distro,
                                             args.image_directory, version],
                                            cwd=output_dir,
                                            check=False)

                if cp_process.returncode != 0:
                    raise OperationFailureError(
                        f"""Executing post image generation script was unsuccessful.
                        Exit code {cp_process.returncode}.""")

    logging.info("Finished")


def init_parser(subparsers):
    """Initialize argument parser"""

    subparser = subparsers.add_parser("batch")

    subparser.add_argument(
        "--output-directory",
        dest="output_directory",
        default="output",
        help="Specify the output directory")

    subparser.add_argument(
        "--repo",
        dest="repo",
        default="torizoncore-oe-nightly-horw",
        help="Toradex Easy Installer source repository")

    subparser.add_argument(
        "--branch",
        dest="branch",
        default="zeus",
        help="TorizonCore OpenEmbedded branch")

    subparser.add_argument(
        "--distro",
        dest="distro",
        nargs='+',
        default=["torizon"],
        help="TorizonCore OpenEmbedded distro")

    subparser.add_argument(
        "--release-type",
        dest="release_type",
        default="nightly",
        help="TorizonCore release type (nightly/monthly/release)")

    subparser.add_argument(
        "--matrix-build-number",
        dest="matrix_build_number",
        help="Matrix build number to processes.")

    subparser.add_argument(
        "--image-directory",
        dest="image_directory",
        default="torizon-core-docker-with-containers",
        help="Image directory name")

    common.add_common_image_arguments(subparser)

    subparser.add_argument(
        "--post-script",
        dest="post_script",
        help="Executes this script in every image generated.")

    common.add_bundle_directory_argument(subparser)

    subparser.add_argument(
        "machines",
        metavar="MACHINE",
        type=str,
        nargs="+",
        help="Machine names to process.")

    subparser.set_defaults(func=do_batch)
