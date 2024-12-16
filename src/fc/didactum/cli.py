import hashlib
import json
import os
import os.path
import re
import socket
import textwrap
import time
import typing
import unicodedata
from typing import Pattern

import click
import prometheus_client
import requests
import sdnotify
import toml
from lxml import etree
from prometheus_client import Gauge, generate_latest


def remove_accents(input_str):
    # as seen in https://stackoverflow.com/a/517974/1509718
    nfkd_form = unicodedata.normalize("NFKD", input_str)
    return "".join([c for c in nfkd_form if not unicodedata.combining(c)])


PATTERN_ALPHANUM_ONLY = re.compile(r"[^a-zA-Z0-9\._\-]+")


def disable_prometheus_default_metrics():
    os.environ["PROMETHEUS_DISABLE_CREATED_SERIES"] = "False"
    prometheus_client.REGISTRY.unregister(prometheus_client.GC_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PLATFORM_COLLECTOR)
    prometheus_client.REGISTRY.unregister(prometheus_client.PROCESS_COLLECTOR)


class DidactumError(RuntimeError):

    error_message: str

    def __init__(self, error_message):
        self.error_message = error_message


class DidactumElement(object):

    id: str
    module: str
    name: str

    class_: str
    type: str
    utype: str

    state: str
    value: float

    @classmethod
    def parse_value(cls, v):
        if v == "-":
            return "n/a"
        return float(v)

    @classmethod
    def from_dict(cls, dict_):
        obj = cls()
        obj.id = dict_["id"]
        obj.module = dict_["module"]
        obj.name = dict_["name"]

        obj.class_ = dict_["clas"]
        obj.type = dict_["type"]
        obj.utype = dict_.get("utype", "")

        obj.state = dict_["state"]
        obj.value = cls.parse_value(dict_["value"])

        return obj

    @classmethod
    def from_node(cls, node):
        return cls.from_dict(dict(node.items()))

    def state_as_sensu_status(self):
        if self.state == "alarm":
            return Sensu.STATE_CRITICAL
        elif "warning" in self.state:
            return Sensu.STATE_WARNING
        return Sensu.STATE_OK

    def name_as_sensu_name(self):
        name = remove_accents(self.name)
        name = PATTERN_ALPHANUM_ONLY.sub("_", name)
        return name

    def type_def(self):
        return "/".join(filter(None, [self.class_, self.type, self.utype]))


class DidactumClient:

    url: str
    username: str
    password: str
    cache_file: str
    session_key: str | None = None
    ignore_element_names: Pattern

    def __init__(
        self, url, username, password, cache_file, ignore_element_names
    ):
        self.url = url
        self.username = username
        self.password = password
        self.cache_file = cache_file
        self.ignore_element_names = re.compile(ignore_element_names)

        if os.path.exists(self.cache_file):
            with open(self.cache_file) as fp:
                self.load_cache(fp)
        else:
            self.login()

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

    def _request(self, querytype, retry_on_auth=True, **kw):
        query = kw.copy()
        query["querytype"] = querytype
        if self.session_key:
            query["k"] = self.session_key
        result = requests.post(self._engine_url, data=query)
        result.raise_for_status()
        result = etree.fromstring(result.text)
        if result.tag == "error":
            error_message = result.get("type")
            if error_message == "authorization error" and retry_on_auth:
                self.login()
                return self._request(querytype, retry_on_auth=False, **kw)
            raise DidactumError(result.get("type"))
        return result

    def _session_key_is_valid(self):
        if not self.session_key:
            return False
        try:
            self._request("logdate")
        except DidactumError as e:
            if e.error_message == "authorization error":
                return False
            raise
        return True

    def login(self):
        result = self._request(
            "auth", name=self.username, h=self.encoded_password
        )
        assert result.tag == "user"
        assert result.get("name") == self.username
        self.session_key = result.get("k")

        with open(self.cache_file, "w") as fp:
            # There's authentication data in there, keep it to ourselves.
            os.chmod(self.cache_file, 0o600)
            self.save_cache(fp)

    def get_elements(self):
        result = []
        modules = self._request("getmodules")
        for element in modules.iter("element"):
            element = DidactumElement.from_node(element)
            if self.ignore_element_names.match(element.name):
                continue
            result.append(element)
        return result


class Sensu:

    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2

    def __init__(self, source, agent_ip, agent_port):
        self.source = source
        self.agent_address = (agent_ip, agent_port)

    def update_check(self, name, status, output):
        result = dict(
            name=name,
            source=self.source,
            status=status,
            output=output,
        )
        msg = json.dumps(result)
        msg = msg.encode("utf-8")
        # Unfortunately Sensu expects a single msg per connection.
        # Reusing the socket doesn't work.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(self.agent_address)
        s.send(msg)
        s.close()


class Application:

    config: dict
    didactum: DidactumClient
    sensu: Sensu

    def load(self, filename):
        with open(filename) as f:
            self.config = config = toml.load(f)

        self.didactum = DidactumClient(**config["didactum"])
        self.sensu = Sensu(**config["sensu"])

    def update_sensu(self):
        for element in self.didactum.get_elements():
            self.sensu.update_check(
                name=element.name_as_sensu_name(),
                status=element.state_as_sensu_status(),
                output=textwrap.dedent(
                    f"""\
                {element.state.upper()}: {element.name} => {element.value} ({element.type_def()})

                module={element.module}
                id={element.id}
                """
                ),
            )

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
@click.pass_context
@click.option("--config", default="fc-didactum.conf")
def cli(ctx, config):
    disable_prometheus_default_metrics()
    ctx.ensure_object(dict)
    ctx.obj["app"] = app = Application()
    app.load(config)


@cli.command
@click.pass_context
def prometheus(ctx):
    app = ctx.obj["app"]
    app.generate_prometheus()


@cli.command
@click.pass_context
@click.option("--continuous/--no-continuous", default=False)
@click.option("--interval", default=10, type=int)
def update_sensu(ctx, continuous, interval):
    app = ctx.obj["app"]
    if not continuous:
        return app.update_sensu()

    n = sdnotify.SystemdNotifier()
    n.notify("READY=1")

    # If this variable is set, systemd expects regular
    # updates that the service is still running
    # otherwise it will kill or restart it (depending on configuration).
    # Ensure that the update interval is set to at most half the configured
    # watchdog interval, see also `WatchdogSec` in systemd.service(5)
    watchdog_interval = os.getenv("WATCHDOG_USEC")

    while True:
        start = time.time()
        print("Polling Didactum and updating Sensu ... ")
        n.notify("STATUS=updating sensu")
        if watchdog_interval:
            n.notify("WATCHDOG=1")

        app.update_sensu()
        end = time.time()
        duration = end - start
        if duration > interval:
            print(
                f"{duration}s polling time larger than desired interval {interval}"
            )
        duration %= interval
        sleep = interval - duration

        n.notify(f"STATUS=sleeping for {sleep:.2f}s")
        print(f"Sleeping for {sleep:.2f}s")
        time.sleep(sleep)


def main():
    cli()
