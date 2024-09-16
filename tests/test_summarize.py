import summarize


def test_extract_kev_empty():
    assert not summarize.extract_kev({})


def test_extract_kev():
    assert summarize.extract_kev(
        {
            "cisaExploitAdd": 1,
            "cisaActionDue": "hi",
            "cisaRequiredAction": "anything",
            "cisaVulnerabilityName": "has to be present",
        }
    )


def test_extract_type_empty():
    assert summarize.extract_type([]) == []


def test_extract_type():
    assert summarize.extract_type(
        [
            {
                "type": "test-type",
                "description": [
                    {"lang": "en", "value": "test-cwe-en"},
                    {"lang": "de", "value": "test-cwe-de"},
                ],
            }
        ]
    ) == [{"type": "test-type", "cwe": "test-cwe-en"}]


def test_extract_type_multi():
    assert summarize.extract_type(
        [
            {
                "type": "test-type-1",
                "description": [
                    {"lang": "en", "value": "test-cwe-en"},
                    {"lang": "de", "value": "test-cwe-de"},
                ],
            },
            {
                "type": "test-type-2",
                "description": [
                    {"lang": "es", "value": "test-cwe-es"},
                    {"lang": "jp", "value": "test-cwe-jp"},
                    {"lang": "en", "value": "test-cwe-en"},
                ],
            },
        ]
    ) == [
        {"type": "test-type-1", "cwe": "test-cwe-en"},
        {"type": "test-type-2", "cwe": "test-cwe-en"},
    ]


def test_summarize_happy_path():
    json_data = ({ "cve": { "id": "CVE-2018-2600", "sourceIdentifier": "secalert_us@oracle.com", "published": "2018-01-18T02:29:19.133", "lastModified": "2018-03-28T01:29:10.933", "vulnStatus": "Modified", "cveTags": [], "descriptions": [ { "lang": "en", "value": "Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Optimizer). Supported versions that are affected are 5.7.20 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.0 Base Score 4.9 (Availability impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H)." }, { "lang": "es", "value": "Vulnerabilidad en el componente MySQL Server en Oracle MySQL (subcomponente: Server: Optimizer). Las versiones compatibles que se han visto afectadas son la 5.7.20 y anteriores. Una vulnerabilidad fácilmente explotable permite que un atacante con un alto nivel de privilegios que tenga acceso a red por medio de múltiples protocolos comprometa la seguridad de MySQL Server. Los ataques exitosos de esta vulnerabilidad pueden resultar en la habilidad no autorizada para provocar un cuelgue o bloqueo repetido frecuentemente (DOS completo) de MySQL Server. CVSS 3.0 Base Score 4.9 (impactos en la disponibilidad). Vector CVSS: (CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H)." } ], "metrics": { "cvssMetricV30": [ { "source": "nvd@nist.gov", "type": "Primary", "cvssData": { "version": "3.0", "vectorString": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H", "attackVector": "NETWORK", "attackComplexity": "LOW", "privilegesRequired": "HIGH", "userInteraction": "NONE", "scope": "UNCHANGED", "confidentialityImpact": "NONE", "integrityImpact": "NONE", "availabilityImpact": "HIGH", "baseScore": 4.9, "baseSeverity": "MEDIUM" }, "exploitabilityScore": 1.2, "impactScore": 3.6 } ], "cvssMetricV2": [ { "source": "nvd@nist.gov", "type": "Primary", "cvssData": { "version": "2.0", "vectorString": "AV:N/AC:L/Au:S/C:N/I:N/A:C", "accessVector": "NETWORK", "accessComplexity": "LOW", "authentication": "SINGLE", "confidentialityImpact": "NONE", "integrityImpact": "NONE", "availabilityImpact": "COMPLETE", "baseScore": 6.8 }, "baseSeverity": "MEDIUM", "exploitabilityScore": 8.0, "impactScore": 6.9, "acInsufInfo": False, "obtainAllPrivilege": False, "obtainUserPrivilege": False, "obtainOtherPrivilege": False, "userInteractionRequired": False } ] }, "weaknesses": [ { "source": "nvd@nist.gov", "type": "Primary", "description": [ { "lang": "en", "value": "NVD-CWE-noinfo" } ] } ], "configurations": [ { "nodes": [ { "operator": "OR", "negate": False, "cpeMatch": [ { "vulnerable": True, "criteria": "cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", "versionStartIncluding": "5.7.0", "versionEndIncluding": "5.7.20", "matchCriteriaId": "BBD4EC79-6A0B-4817-B062-42E3DFD8FE86" } ] } ] } ], "references": [ { "url": "http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html", "source": "secalert_us@oracle.com", "tags": [ "Patch", "Vendor Advisory" ] }, { "url": "http://www.securityfocus.com/bid/102696", "source": "secalert_us@oracle.com", "tags": [ "Third Party Advisory", "VDB Entry" ] }, { "url": "http://www.securitytracker.com/id/1040216", "source": "secalert_us@oracle.com", "tags": [ "Third Party Advisory", "VDB Entry" ] }, { "url": "https://access.redhat.com/errata/RHSA-2018:0586", "source": "secalert_us@oracle.com" }, { "url": "https://security.netapp.com/advisory/ntap-20180117-0002/", "source": "secalert_us@oracle.com", "tags": [ "Third Party Advisory" ] }, { "url": "https://usn.ubuntu.com/3537-1/", "source": "secalert_us@oracle.com" } ] } })

    assert summarize.summarize(json_data) == { 'has_kev': False, 'id': 'CVE-2018-2600', 'lastModified': '2018-03-28T01:29:10.933', 'published': '2018-01-18T02:29:19.133', 'severities': [ { 'severity': 'MEDIUM', 'type': 'Primary', }, { 'severity': 'MEDIUM', 'type': 'Primary', }, ], 'types': [ { 'cwe': 'NVD-CWE-noinfo', 'type': 'Primary' } ] }
