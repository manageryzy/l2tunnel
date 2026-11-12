"""Console entry point for the tunnel simulator."""

import argparse
from pathlib import Path

from .config import Experiment, load_experiment
from .experiment import run_experiment


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, help="Experiment TOML. Defaults to the built-in sweep.")
    parser.add_argument("--out", type=Path, default=Path("work/sim"),
                        help="New directory for results (default: work/sim).")
    args = parser.parse_args(argv)
    try:
        if args.out.exists():
            raise FileExistsError(f"output already exists: {args.out}")
        experiment = load_experiment(args.config) if args.config else Experiment()
        run_experiment(experiment, args.out)
    except (OSError, TypeError, ValueError) as error:
        parser.error(str(error))
    print(f"Results written to {args.out.resolve()}")


if __name__ == "__main__":
    main()
