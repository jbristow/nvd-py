import os
import time

import files
from db import DbClient
from jsondl import download_page
from summarize import summarize_and_write


def filename(folder: str, n: int) -> str:
    return f"{folder}/init-data-{n}.json"


def globname(folder: str) -> str:
    return f"{folder}/init-data-*.json"


def define_subcommand(subparsers):
    init_parser = subparsers.add_parser("init")
    init_parser.add_argument("--json-dir", default="downloaded")
    init_parser.add_argument("--database", default="cve.duck")
    init_parser.add_argument("--skip-dl", action="store_true")
    init_parser.add_argument("-k", "--api-key", required=True)


def run_subcommand(args) -> None:
    api_key = args.api_key
    dbclient = DbClient(args.database)
    dl_folder = args.json_dir

    dir_exists = os.path.exists(dl_folder)

    if not args.skip_dl:
        if not dir_exists:
            os.mkdir(dl_folder)
        files.remove_old(globname(dl_folder))
        download_json(api_key, dl_folder)
    dbclient.create(globname(dl_folder))


def download_json(api_key, dl_folder):
    index = 0
    page = 0

    data = download_page(api_key, index=0)
    per_page = data["resultsPerPage"]
    total_results = data["totalResults"]

    summarize_and_write(data["vulnerabilities"], filename(dl_folder, page))
    print(f"Downloaded {filename(dl_folder, page)} ({index}/{total_results})")
    index += per_page
    page += 1

    while index < total_results:
        time.sleep(3)
        data = download_page(api_key, index=index)
        summarize_and_write(data["vulnerabilities"], filename(dl_folder, page))
        print(f"Downloaded {filename(dl_folder, page)} ({index}/{total_results})")
        page += 1
        index += per_page
