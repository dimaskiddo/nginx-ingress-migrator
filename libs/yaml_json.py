#!/usr/bin/env python3
# JSON -> YAML in the style used by exports/: multi-line strings become literal block
# scalars (| / |-) so snippets stay readable, and keys keep their input order so the
# exported manifest matches the plan.
import json
import sys

import yaml


class Dumper(yaml.SafeDumper):
    pass


def represent_str(dumper, data):
    style = "|" if "\n" in data else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style=style)


Dumper.add_representer(str, represent_str)

data = json.load(sys.stdin)

sys.stdout.write(yaml.dump(data, Dumper=Dumper, sort_keys=False,
                           default_flow_style=False, allow_unicode=True))
