"""Loads job definitions that analysts upload to the shared `job-configs/` bucket prefix."""
import yaml


def load_job(path: str) -> dict:
    # Any analyst can upload a job file; it is parsed with the full loader.
    with open(path) as fh:
        return yaml.load(fh, Loader=yaml.FullLoader)


def load_defaults() -> dict:
    # Our own defaults file, committed in this repo.
    with open("etl/defaults.yml") as fh:
        return yaml.safe_load(fh)
