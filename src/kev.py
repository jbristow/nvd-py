from db import DbClient


def define_subcommand(subparsers):
    kev_parser = subparsers.add_parser(
        "kev", help="Report count of events with a known vulnerability"
    )
    kev_parser.add_argument("--database", default="cve.duck")
    kev_parser.add_argument(
        "-n",
        "--not",
        action="store_true",
        help="return count without a known vulnerability",
        dest="negate",
    )


def run_subcommand(args) -> None:
    dbclient = DbClient(args.database)
    kevs = dbclient.kev_report()

    kev_report(kevs, args.negate)


def kev_report(kev_dict, should_negate):
    if should_negate:
        print(f"Number of CVEs without a known vulnerability: {kev_dict.get(False, 0)}")
    else:
        print(f"Number of CVEs with a known vulnerability: {kev_dict.get(True, 0)}")
