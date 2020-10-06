import json
from urllib.parse import urlparse

import requests
from dateutil import parser as dateutil_parser

from api_app.exceptions import AnalyzerRunException
from api_app.script_analyzers import classes
from intel_owl import secrets


class DNSdb(classes.ObservableAnalyzer):
    """Firesight passive DNS API

    Support different server.
    Support version 1 and 2.
    Allow filter on rrtype, count value and timestamp on time fields.
    Allow different query types: normal, with left or right wildcard and nameserver.
    """

    def set_config(self, additional_config_params):
        api_key_name = additional_config_params.get("api_key_name", "DNSDB_KEY")
        self.__api_key = secrets.get_secret(api_key_name)

        self.dnsdb_server = additional_config_params.get("server", "api.dnsdb.info")
        self.api_version = additional_config_params.get("api_version", 2)

        self.query_type = additional_config_params.get("query_type", "domain")

        self.limit = additional_config_params.get("limit", 10000)
        self.max_count = additional_config_params.get("max_count", 0)
        self.first_before = additional_config_params.get("first_before", "3000-12-31")
        self.first_after = additional_config_params.get("first_after", "1970-1-1")
        self.last_before = additional_config_params.get("last_before", "3000-12-31")
        self.last_after = additional_config_params.get("last_after", "1970-1-1")
        self.rrtype = additional_config_params.get("rrtype", "")

    def run(self):
        query_types = [
            "domain",
            "rrname-wildcard-left",
            "rrname-wildcard-right",
            "names",
            "rdata-wildcard-left",
            "rdata-wildcard-right",
        ]
        # empty means all rrtypes
        # ANY-DNSSEC is an API-specific rrtype that represent all DNSSEC rrtypes
        supported_rrtype = [
            "",
            "A",
            "AAAA",
            "ALIAS",
            "CNAME",
            "MX",
            "NS",
            "PTR",
            "SOA",
            "SRV",
            "TXT",
            "ANY-DNSSEC",
        ]
        supported_version = [1, 2]

        # validate analyzer params
        if not self.__api_key:
            raise AnalyzerRunException("no api key retrieved")

        if self.api_version not in supported_version:
            raise AnalyzerRunException(
                f"{self.api_version} not supported version,"
                f"available versions: {supported_version}"
            )

        if self.api_version == 1:
            api_version = ""
            header_application_type = "application/json"
        elif self.api_version == 2:
            api_version = "/dnsdb/v2"
            header_application_type = "application/x-ndjson"
        else:
            raise AnalyzerRunException(
                f"{self.api_version} not supported version,"
                f"available versions: {supported_version}"
            )

        if self.query_type:
            if self.query_type not in query_types:
                raise AnalyzerRunException(
                    f"{self.query_type} not in available query types"
                )

        if not isinstance(self.limit, int):
            raise AnalyzerRunException(
                f"limit: {self.limit} ({type(self.limit)}) must be a integer"
            )

        if not isinstance(self.max_count, int):
            raise AnalyzerRunException(
                f"limit: {self.max_count} ({type(self.max_count)}) must be a integer"
            )

        first_before = self._convert_date_type(self.first_before)
        first_after = self._convert_date_type(self.first_after)
        last_before = self._convert_date_type(self.last_before)
        last_after = self._convert_date_type(self.last_after)

        if str(self.rrtype) not in supported_rrtype:
            raise AnalyzerRunException(
                f"{self.rrtype} is not a valid rrtype: {supported_rrtype}"
            )

        # perform DNSsb API request
        headers = {"Accept": header_application_type, "X-API-Key": self.__api_key}

        observable_to_check = self.observable_name
        # for URLs we are checking the relative domain
        if self.observable_classification == "url":
            observable_to_check = urlparse(self.observable_name).hostname

        if self.observable_classification == "ip":
            endpoint = "rdata/ip"
        elif self.observable_classification in ["domain", "url"]:
            if self.query_type == "domain":
                endpoint = "rrset/name"
            elif self.query_type == "rrname-wildcard-left":
                endpoint = "rrset/name"
                observable_to_check = "*." + observable_to_check
            elif self.query_type == "rrname-wildcard-right":
                endpoint = "rrset/name"
                observable_to_check += ".*"
            elif self.query_type == "names":
                endpoint = "rdata/name"
            elif self.query_type == "rdata-wildcard-left":
                endpoint = "rdata/name"
                observable_to_check = "*." + observable_to_check
            elif self.query_type == "rdata-wildcard-right":
                endpoint = "rdata/name"
                observable_to_check += observable_to_check + ".*"
            else:
                raise AnalyzerRunException(f"{self.query_type} not supported")
        else:
            raise AnalyzerRunException(
                f"{self.observable_classification} not supported"
            )

        url = (
            f"https://{self.dnsdb_server}{api_version}/lookup/{endpoint}"
            f"/{observable_to_check}/{self.rrtype}"
        )
        params = {"limit": self.limit}
        response = requests.get(url, params=params, headers=headers)
        response.raise_for_status()
        results_list = response.text

        # different versions have different parsers
        json_extracted_results = []
        if self.api_version == 2:
            # first elem is a context line, last two are a context line and a empty line
            for item in results_list.split("\n")[1:-2]:
                if item:
                    new_element = json.loads(item)
                    # response element is wrapped in object field
                    json_extracted_results.append(new_element["obj"])
        elif self.api_version == 1:
            for item in results_list.split("\n"):
                if item:
                    json_extracted_results.append(json.loads(item))
        else:
            raise AnalyzerRunException(
                f"{self.api_version} not supported version, "
                f"available versions: {supported_version}"
            )

        # filter results for max count value
        if self.max_count > 0:
            json_extracted_results = [
                elem
                for elem in json_extracted_results
                if elem["count"] <= self.max_count
            ]
        # filter results time_first before
        json_extracted_results = [
            elem
            for elem in json_extracted_results
            if self._retrieve_element_time(elem, "first") <= first_before
        ]
        # filter results time_first after
        json_extracted_results = [
            elem
            for elem in json_extracted_results
            if self._retrieve_element_time(elem, "first") >= first_after
        ]
        # filter results time_last before
        json_extracted_results = [
            elem
            for elem in json_extracted_results
            if self._retrieve_element_time(elem, "last") <= last_before
        ]
        # filter results time_last after
        json_extracted_results = [
            elem
            for elem in json_extracted_results
            if self._retrieve_element_time(elem, "last") >= last_after
        ]

        return json_extracted_results

    def _convert_date_type(self, date_string):
        """Convert date into timestamp

        :param date_string: date to be converted into timestamp
        :type date_string: str
        :return: date timestamp
        :rtype: int
        """
        try:
            return dateutil_parser.parse(date_string).timestamp()
        except ValueError:
            error_message = f"{date_string} cannot be converted to a valid datetime"
        except TypeError:
            error_message = (
                f"{type(date_string)} is not a string and cannot be "
                f"converted to a datetime "
            )
        except Exception:
            error_message = (
                f"{date_string} with type: {type(date_string)},"
                f"something wrong happened during conversion to datetime"
            )

        raise AnalyzerRunException(error_message)

    def _retrieve_element_time(self, element, time_key):
        """Element can have time_first/last or time_zone_first/last It is not
        predictable which one is in response check them when one is find return its
        value

        :param element: key of time filed: first or last
        :param time_key: str
        :return: element timestamp
        :rtype: int
        """
        zone_time_field = "zone_time_" + time_key
        time_field = "time_" + time_key
        if element.get(zone_time_field, ""):
            return element[zone_time_field]
        if element.get(time_field, ""):
            return element[time_field]

        raise AnalyzerRunException(
            f"{element} do not have bot time_zone_{time_key}, time_{time_key}"
        )
