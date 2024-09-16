import time
from argparse import Namespace
from datetime import datetime, timezone

import files
from db import DbClient
from jsondl import download_page
from summarize import summarize_and_write


def filename(folder: str, n: int) -> str:
    return f"{folder}/update-data-{n}.json"


def globname(folder: str) -> str:
    return f"{folder}/update-data-*.json"


def define_subcommand(subparsers):
    update_parser = subparsers.add_parser(
        "update", help="Update the local database with recently modified CVEs"
    )
    update_parser.add_argument("--json-dir", default="downloaded")
    update_parser.add_argument("--database", default="cve.duck")
    update_parser.add_argument("-k", "--api-key", required=True)


def run_subcommand(args: Namespace):
    api_key = args.api_key
    dbclient = DbClient(args.database)
    dl_folder = args.json_dir

    last_updated = dbclient.get_last_modified()

    files.remove_old(globname(dl_folder))

    total_results = download_json(api_key, dl_folder, last_updated)
    if total_results:
        print(f"Updating db with {total_results} updates.")
        dbclient.update(globname(dl_folder))
    else:
        print("Nothing to update.")


def download_json(api_key: str, dl_folder: str, last_updated: datetime) -> int:
    index = 0
    page = 0
    end_time = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
    start_time = last_updated.isoformat(timespec="milliseconds")
    data = download_page(api_key, start_time, end_time, 0)
    per_page = data["resultsPerPage"]
    total_results = data["totalResults"]
    summarize_and_write(data["vulnerabilities"], filename(dl_folder, page))
    print(f"Downloaded {filename(dl_folder, page)} ({index}/{total_results})")

    index += per_page
    page += 1

    while index < total_results:
        time.sleep(3)
        data = download_page(api_key, start_time, end_time, index)
        summarize_and_write(data["vulnerabilities"], filename(dl_folder, page))
        print(f"Downloaded {filename(dl_folder, page)} ({index}/{total_results})")
        page += 1
        index += per_page
    return total_results
