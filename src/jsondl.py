import requests

nvd_uri = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def download_page(api_key, start=None, end=None, index=0):
    query_params = {"startIndex": index}
    if start and end:
        query_params["lastModStartDate"] = start
        query_params["lastModEndDate"] = end
    response = requests.get(
        nvd_uri,
        auth=("user", "pass"),
        headers={"apiKey": api_key},
        params=query_params,
    )
    if response.status_code != 200:
        print("Error:", response.text)
    response.raise_for_status()
    return response.json()
