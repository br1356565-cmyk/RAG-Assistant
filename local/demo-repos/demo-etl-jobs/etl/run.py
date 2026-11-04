"""Entry point: python -m etl.run <job.yml> <day>"""
import sys

from .load_config import load_defaults, load_job
from .partner_pull import pull


def main() -> None:
    job = {**load_defaults(), **load_job(sys.argv[1])}
    data = pull(sys.argv[2])
    print(f"job {job.get('name', '?')}: {len(data)} bytes, batch {job['batch_size']}")


if __name__ == "__main__":
    main()
