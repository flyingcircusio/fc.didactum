import requests
import hashlib
from lxml import etree
import typing
import sys
import socket

import json
import os
import os.path
from prometheus_client import Gauge, generate_latest
import prometheus_client
import click

STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2

CACHE_FILE = "/tmp/fc.didactum.cache"


class DidactumError(RuntimeError):

    error_message: str

    def __init__(self, error_message):
        self.error_message = error_message


class DidactumClient:

    url: str
    username: str
    password: str
    session_key: str | None = None

    def __init__(
        self,
        url,
        username,
        password,
        sensu_source,
    ):
        self.url = url
        self.username = username
        self.password = password
        self.sensu_source = sensu_source

    def load_cache(self, fp: typing.IO):
        data = json.load(fp)
        self.session_key = data["session_key"]

    def save_cache(self, fp: typing.IO):
        data = {"session_key": self.session_key}
        json.dump(data, fp)

    @property
    def _engine_url(self):
        return f"{self.url}/engine.htm"

    @property
    def encoded_password(self):
        return hashlib.sha1(self.password.encode("ascii")).hexdigest()

    def _request(self, querytype, **kw):
        kw["querytype"] = querytype
        if self.session_key:
            kw["k"] = self.session_key
        result = requests.post(self._engine_url, data=kw)
        result.raise_for_status()
        result = etree.fromstring(result.text)
        if result.tag == "error":
            raise DidactumError(result.get("type"))
        return result

    def _session_key_is_valid(self):
        if not self.session_key:
            return False
        try:
            print("Validating session")
            self._request("logdate")
        except DidactumError as e:
            if e.error_message == "authorization error":
                return False
            raise
        return True

    def login(self):
        if self._session_key_is_valid():
            return
        print("performing log in")
        result = self._request("auth", name=self.username, h=self.encoded_password)
        assert result.tag == "user"
        assert result.get("name") == self.username
        self.session_key = result.get("k")

    def process_element(self, element):
        element_state = element.get("state")
        element_name = element.get("name")
        element_id = element.get("id")
        element_type = element.get("type")
        element_value = element.get("value")

        state = STATE_OK

        result = dict(
            name=element_name,
            source=self.sensu_source,
            status=STATE_OK,
            output=f"{element_state.upper()}: {element_name} {element_type}={element_value} id={element_id}",
        )

        if element_state == "alarm":
            result["status"] = STATE_CRITICAL
        elif "warning" in element_state:
            result["status"] = STATE_WARNING

        msg = json.dumps(result)
        msg = msg.encode("utf-8")
        import pdb

        pdb.set_trace()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", 3030))
            sock.send(msg)
            sock.close()
        except Exception:
            return

        return

    def check_states(self):
        modules = self._request("getmodules")
        for element in modules.iter("element"):
            self.process_element(element)

    def generate_prometheus(self, fp: typing.IO):
        modules = self._request("getmodules")

        for element in modules.iter("element"):
            element = element.attrib

            # ['id', 'module', 'num', 'clas', 'type', 'name', 'state', 'value', 'view', 'um']
            if element["value"] != "-":
                g = Gauge(
                    f"didactum_element_{element['id']}",
                    f"Value for `{element['name']}`",
                )
                g.set(element["value"])
            state = Gauge(
                f"didactum_element_{element['id']}_state",
                f"State for `{element['name']}`",
                ["state"],
            )
            # XXX get full list of states
            for candidate in ["normal", "off", "on", "alarm", "low warning"]:
                s = state.labels(candidate)
                s.set(1.0 if element["state"] == candidate else 0.0)

        # This isn't good WRT to performance, but I don't expect more than a
        # few kb of output here.
        fp.write(generate_latest().decode("utf-8"))


@click.group()
def cli():
    pass


@cli.command
def prometheus():
    os.environ["PROMETHEUS_DISABLE_CREATED_SERIES"] = "False"
    prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

    c = DidactumClient(
        "http://localhost:8081",
        username="admin",
        password="admin",
        sensu_source="didactum00",
    )
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as fp:
            c.load_cache(fp)
    c.login()
    with open(CACHE_FILE, "w") as fp:
        c.save_cache(fp)
    c.generate_prometheus(sys.stdout)


@cli.command
def check():
    os.environ["PROMETHEUS_DISABLE_CREATED_SERIES"] = "False"
    prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)

    c = DidactumClient(
        "http://localhost:8081",
        username="admin",
        password="admin",
        sensu_source="didactum00",
    )
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE) as fp:
            c.load_cache(fp)
    c.login()
    with open(CACHE_FILE, "w") as fp:
        c.save_cache(fp)
    c.check_states()


def main():
    cli()
