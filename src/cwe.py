from db import DbClient


def define_subcommand(subparsers):
    cwe_parser = subparsers.add_parser("cwe", help="Summary of CWEs")
    cwe_parser.add_argument("--database", default="cve.duck")
    cwe_parser.add_argument(
        "-p",
        "--primary",
        action="append_const",
        dest="types",
        const="p",
        help="Include Primary",
    )
    cwe_parser.add_argument(
        "-s",
        "--secondary",
        action="append_const",
        dest="types",
        const="s",
        help="Include Secondary",
    )
    cwe_parser.add_argument(
        "-c",
        "--combined",
        action="append_const",
        dest="types",
        const="c",
        help="Include Combined",
    )
    cwe_parser.add_argument(
        "-l", "--limit", type=int, default=0, help="Limit to the top LIMIT cves"
    )


all_types = ["p", "s", "c"]


def sort_total(curr):
    return sum(curr.values())


def cwe_report(curr_dict, included, limit=0):
    header = "CWEs"
    if not included or "p" in included:
        header += " Primary"
    if not included or "s" in included:
        header += " Secondary"
    if not included or "c" in included:
        header += " Combined"

    max_cwe_len = max(len(k) for k in curr_dict.keys())
    max_p_len = max(
        len("Primary"), max(len(str(v.get("Primary", 0))) for v in curr_dict.values())
    )
    max_s_len = max(
        len("Secondary"),
        max(len(str(v.get("Secondary", 0))) for v in curr_dict.values()),
    )
    max_c_len = max(
        len("Combined"), max(len(str(v.get("Combined", 0))) for v in curr_dict.values())
    )

    header = ["CWE".ljust(max_cwe_len)]
    underline = ["-".ljust(max_cwe_len, "-")]
    if not included or "p" in included:
        header.append("Primary".rjust(max_p_len))
        underline.append("-".rjust(max_p_len, "-"))
    if not included or "s" in included:
        header.append("Secondary".rjust(max_s_len))
        underline.append("-".rjust(max_s_len, "-"))
    if not included or "c" in included:
        header.append("Combined".rjust(max_c_len))
        underline.append("-".rjust(max_c_len, "-"))

    print(" | ".join(header))
    print("-|-".join(underline))
    keys = sorted(
        curr_dict.keys(), key=lambda x: sort_total(curr_dict.get(x, {})), reverse=True
    )
    if limit > 0:
        keys = keys[0:limit]

    for label in keys:
        count = curr_dict.get(label, 0)
        output = [label.ljust(max_cwe_len)]
        if not included or "p" in included:
            output.append(str(count.get("Primary", 0)).rjust(max_p_len))
        if not included or "s" in included:
            output.append(str(count.get("Secondary", 0)).rjust(max_s_len))
        if not included or "c" in included:
            output.append(str(count.get("Combined", 0)).rjust(max_c_len))
        print(" | ".join(output))
    print()


def run_subcommand(args) -> None:
    dbclient = DbClient(args.database)

    if not args.types or all(t in args.types for t in all_types):
        report = dbclient.cwe_report()
    else:
        report = dbclient.cwe_report(
            primary="p" in args.types,
            secondary="s" in args.types,
            combined="c" in args.types,
        )

    last_cwe = None
    curr_dict = {}
    for line in sorted(report, key=lambda x: str(x[1])):
        curr_type = line[0] if line[0] else "UNDEFINED"
        curr_cwe = line[1] if line[1] else "UNDEFINED"
        if last_cwe != curr_cwe:
            curr_dict[curr_cwe] = {curr_type: line[2]}
            last_cwe = curr_cwe
        else:
            curr_dict[curr_cwe][curr_type] = line[2]
    curr_dict.pop("UNDEFINED")

    cwe_report(curr_dict, args.types, args.limit)
