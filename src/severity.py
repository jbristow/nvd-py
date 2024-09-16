from db import DbClient


def define_subcommand(subparsers):
    sev_parser = subparsers.add_parser("severity")
    sev_parser.add_argument("--database", default="cve.duck")
    sev_parser.add_argument(
        "-p", "--primary", action="append_const", dest="types", const="p"
    )
    sev_parser.add_argument(
        "-s", "--secondary", action="append_const", dest="types", const="s"
    )
    sev_parser.add_argument(
        "-c", "--combined", action="append_const", dest="types", const="c"
    )


all_types = ["p", "s", "c"]


def sort_sev(row):
    output = 1
    if row[0] == "Primary":
        output *= 10
    elif row[0] == "Secondary":
        output *= 20
    elif row[0] == "Combined":
        output *= 30

    if row[1] == "CRITICAL":
        output += 1
    elif row[1] == "HIGH":
        output += 2
    elif row[1] == "MEDIUM":
        output += 3
    elif row[1] == "LOW":
        output += 4
    elif row[1] == "NONE":
        output += 5
    else:
        output += 6
    return output


def run_subcommand(args) -> None:
    dbclient = DbClient(args.database)

    if not args.types or all(t in args.types for t in all_types):
        report = dbclient.severity_report()
    else:
        report = dbclient.severity_report(
            primary="p" in args.types,
            secondary="s" in args.types,
            combined="c" in args.types,
        )

    last_type = None
    curr_dict = {}
    for line in sorted(report, key=lambda x: sort_sev(x)):
        curr_type = line[0] if line[0] else "UNDEFINED"
        curr_sev = line[1] if line[1] else "UNDEFINED"
        if last_type != curr_type:
            curr_dict[curr_type] = {curr_sev: line[2]}
            last_type = curr_type
        else:
            curr_dict[curr_type][curr_sev] = line[2]
    curr_dict.pop("UNDEFINED")

    if not args.types or "p" in args.types:
        sev_report(curr_dict, "Primary")

    if not args.types or "s" in args.types:
        sev_report(curr_dict, "Secondary")

    if not args.types or "c" in args.types:
        sev_report(curr_dict, "Combined")


def sev_report(curr_dict, sev_type: str):
    print(f"Base Severity ({sev_type})")
    print(f"CRITICAL:    {curr_dict.get(sev_type, {}).get("CRITICAL", 0)}")
    print(f"HIGH:        {curr_dict.get(sev_type, {}).get("HIGH", 0)}")
    print(f"MEDIUM:      {curr_dict.get(sev_type, {}).get("MEDIUM", 0)}")
    print(f"LOW:         {curr_dict.get(sev_type, {}).get("LOW", 0)}")
    print(f"NONE:        {curr_dict.get(sev_type, {}).get("NONE", 0)}")
    print(f"(UNDEFINED): {curr_dict.get(sev_type, {}).get("UNDEFINED", 0)}")
    print()
