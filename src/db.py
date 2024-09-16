from datetime import datetime

import duckdb
from duckdb.duckdb import DuckDBPyConnection


class DbClient:
    def __init__(self, db_file):
        self.db_file = db_file

    def connect(self, ro: bool = False) -> DuckDBPyConnection:
        return duckdb.connect(database=self.db_file, read_only=ro)

    def json_update(self, file_glob: str) -> None:
        con = self.connect()
        # on conflict update doesn't work yet
        con.execute(
            "DELETE FROM cves WHERE id in (SELECT id FROM read_json(?));", [file_glob]
        )
        con.execute(
            "INSERT INTO cves BY NAME SELECT * FROM read_json(?, format = 'array');",
            [file_glob],
        )
        con.close()

    def get_last_modified(self) -> datetime:
        con = self.connect(True)
        con.execute("SELECT max(lastModified) AS lastModified FROM cves;")
        result = con.fetchone()[0]
        con.close()
        return datetime.fromisoformat(f"{result}Z")

    def create(self, dl_folder_glob: str):
        con = self.connect()
        con.execute(
            "CREATE TABLE cves AS SELECT * FROM read_json(?)",
            [f"{dl_folder_glob}"],
        )
        con.execute("CREATE UNIQUE INDEX cve_id_idx ON cves (id);")
        con.execute(
            "CREATE VIEW types AS SELECT id, unnest(types).type AS type, unnest(types).cwe AS cwe FROM cves;"
        )
        con.execute(
            "CREATE VIEW severities AS SELECT id, unnest(severities).type AS type, unnest(severities).severity AS severity FROM cves;"
        )
        con.close()

    def update(self, file_glob: str):
        con = self.connect()
        # on conflict update doesn't work yet
        con.execute(
            "DELETE FROM cves WHERE id in " "(SELECT id FROM read_json(?));",
            [file_glob],
        )
        con.execute(
            "INSERT INTO cves BY NAME " "SELECT * FROM read_json(?, format = 'array');",
            [file_glob],
        )
        con.close()

    def severity_report(self, primary=True, secondary=True, combined=True):

        where = "  WHERE 1=1"
        if not primary:
            where += " AND type<>'Primary' "
        if not secondary:
            where += " AND type<>'Secondary' "
        if not combined:
            where += " AND type<>'Combined' "

        con = self.connect(True)
        con.execute(
            "with combo as ("
            "  (select distinct type, severity, id from severities) "
            "  union "
            "  (select distinct 'Combined', severity, id from severities)"
            ") select type, severity, count(distinct id) as amount "
            "  from combo "
            f" {where}"
            "  group by rollup (type, severity) "
            "  order by type, severity, amount;",
            [],
        )
        output = con.fetchall()
        con.close()
        return output

    def cwe_report(self, primary=True, secondary=True, combined=True):

        where = "  WHERE 1=1"
        if not primary:
            where += " AND type<>'Primary' "
        if not secondary:
            where += " AND type<>'Secondary' "
        if not combined:
            where += " AND type<>'Combined' "

        con = self.connect(True)
        con.execute(
            "with combo as ("
            "  (select distinct type, cwe, id from types) "
            "  union "
            "  (select distinct 'Combined', cwe, id from types)"
            ") select type, cwe, count(distinct id) as amount "
            "  from combo "
            f" {where}"
            "  group by rollup (type, cwe) "
            "  order by type, cwe, amount;",
            [],
        )
        output = con.fetchall()
        con.close()
        return output

    def kev_report(self):
        con = self.connect(True)
        con.execute("select has_kev, count(distinct id) as amount from cves group by has_kev;",[])
        output = {k:v for k,v in con.fetchall()}
        con.close()
        return output
