import argparse

import cwe
import init
import kev
import severity
import update


def main():
    parser = argparse.ArgumentParser(prog="nvb", description="Nvb CVE Api summarizer")
    subparsers = parser.add_subparsers(title="subcommands", required=True, dest="cmd")
    init.define_subcommand(subparsers)
    update.define_subcommand(subparsers)
    severity.define_subcommand(subparsers)
    cwe.define_subcommand(subparsers)
    kev.define_subcommand(subparsers)

    args = parser.parse_args()

    if args.cmd == "init":
        init.run_subcommand(args)
    elif args.cmd == "update":
        update.run_subcommand(args)
    elif args.cmd == "severity":
        severity.run_subcommand(args)
    elif args.cmd == "cwe":
        cwe.run_subcommand(args)
    elif args.cmd == "kev":
        kev.run_subcommand(args)


if __name__ == "__main__":
    main()
