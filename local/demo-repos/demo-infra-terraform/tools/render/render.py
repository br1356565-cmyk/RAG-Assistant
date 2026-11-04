"""Renders terraform.tfvars files from templates committed in this repo (run in CI).
Template text never comes from users: only from files reviewed in pull requests."""
import pathlib
import sys

from jinja2 import Environment, FileSystemLoader, StrictUndefined

HERE = pathlib.Path(__file__).parent


def render(name: str, **values) -> str:
    env = Environment(loader=FileSystemLoader(HERE / "templates"), undefined=StrictUndefined, autoescape=False)
    return env.get_template(name).render(**values)


if __name__ == "__main__":
    print(render(sys.argv[1], environment=sys.argv[2]))
