## Simple NVD Summary Browser

### Installation/Setup

* Requires Python 12+
* A valid key for the nvd api. https://nvd.nist.gov/developers/start-here

### Running the browser

#### Display cli help
```shell
python src/nvd.py -h
```

#### Initialize the db.
To set up the database for the first time, this program first scrapes all
current CVE entries from the database and summarizes them.

**Warning:** this takes about 10 minutes, and while the summarization process
is not overly-efficient, speeding up the process would put the user at odds
with the NIST recommendation that you leave about 6 seconds between each API
ping.

```
python src/nvd.py init -k <<YOUR KEY HERE>>
```

If you want to change where the database and temp files get saved, you can do
that with cli options, but be warned that you will need to add them to your
future cli calls.

```
python src/nvd.py init -k <<API_KEY>> \
  --database path/to/db.file \
  --json-dir path/to/tempdir
```

A `--skip-dl` option is also available if you already have the downloaded files available.

#### Update the db

If you've already initialized the DB, running the `update` subcommand will get
any changes to the CVE db and re-summarize the associated CVEs.

This subcommand uses the same flags as the init.

#### View the Summary reports

There are three summary report subcommands: `severity`, `kev`, and `cwe`

```
python src/nvd.py severity
python src/nvd.py cwe
python src/nvd.py kev
```

The `severity` subcommand returns the count of cves in the database for all
severity levels. This value is based off of the cvssData provided in some cves.
This data is not present on all cves, and those cves are marked as having an
`(UNDEFINED)` status in the report.  The `type` identifies whether the
organization that provided the CVSS data is a primary or secondary source.
Primary sources include the NVD and CNA who have reached the provider level in
CVMAP. 10% of provider level submissions are audited by the NVD. If a
submission has been audited the NVD will appear as the primary source and the
provider level CNA will appear as the secondary source.

The `cwe` subcommand returns a list of the CWEs observed in the CVE database,
and whether they were observed by a Primary or Secondary source. This list can
be limited to the top `n` total reported CWE names with `-l n`

The `kev` subcommand simply returns a count of the number of CVE entries that
have been listed in CISA's Known Exploited Vulnerabilities (KEV) Catalog. The
CVE summary is marked `True` if all of the required properties (cisaExploitAdd,
cisaActionDue, cisaRequiredAction, and cisaVulnerabilityName) are present.
