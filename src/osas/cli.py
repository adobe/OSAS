# Copyright 2024 Adobe. All rights reserved.
# This file is licensed to you under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License. You may obtain a copy
# of the License at http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
# OF ANY KIND, either express or implied. See the License for the specific language
# governing permissions and limitations under the License.

import os
import os.path
import sys
import click
from decouple import config
import warnings

warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=Warning)


def app_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return

    from importlib.metadata import version

    osas_version = version("osas")

    click.echo(f"OSAS {osas_version}")
    ctx.exit()


@click.group()
@click.option(
    "--version",
    is_flag=True,
    callback=app_version,
    expose_value=False,
    is_eager=True,
    help="Show the version and exit.",
)
def main():
    pass


@click.group()
def ingest():
    pass

if __name__ == "__main__":
    # disable all TQDM output
    main()