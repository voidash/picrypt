#!/usr/bin/env python3
"""
picrypt functional test runner.

Usage:
    ./entry.py                  # run all tests
    ./entry.py -t test_name     # run specific test
    ./entry.py -g basic         # run test group
    ./entry.py --list           # list available tests
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

import flexitest
from flexitest.runtime import load_candidate_modules, scan_dir_for_modules

from common.config import ServiceType
from envconfigs.basic import BasicEnv, BasicEnvWithPin
from factories.server import PicryptServerFactory


def setup_logging():
    level = os.environ.get("LOG_LEVEL", "INFO")
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def parse_args():
    parser = argparse.ArgumentParser(description="picrypt functional tests")
    parser.add_argument("-t", "--tests", nargs="*", help="Run specific test(s) by name")
    parser.add_argument("-g", "--groups", nargs="*", help="Run test group(s)")
    parser.add_argument("--list", action="store_true", help="List available tests")
    parser.add_argument("tests_pos", nargs="*", help="Positional test names")
    return parser.parse_args()


def find_binary() -> str:
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for path in [
        os.path.join(repo_root, "target", "release", "picrypt-server"),
        os.path.join(repo_root, "target", "debug", "picrypt-server"),
    ]:
        if os.path.isfile(path):
            return path
    print("ERROR: picrypt-server binary not found.")
    print("Run: cargo build --release -p picrypt-server")
    sys.exit(1)


def main() -> int:
    args = parse_args()
    setup_logging()

    root_dir = os.path.dirname(os.path.abspath(__file__))
    test_dir = os.path.join(root_dir, "tests")

    # List mode
    if args.list:
        modules = scan_dir_for_modules(test_dir)
        print("\nAvailable tests:")
        for name in sorted(modules.keys()):
            print(f"  {name}")
        print(f"\nTotal: {len(modules)}")
        return 0

    binary = find_binary()
    logging.info(f"Using binary: {binary}")

    # Factories
    factories = {
        ServiceType.PicryptServer: PicryptServerFactory(
            port_range=range(17100, 17200),
            binary_path=binary,
        ),
    }

    # Environments
    global_envs: dict[str, flexitest.EnvConfig] = {
        "basic": BasicEnv(),
        "basic_with_pin": BasicEnvWithPin(),
        "rate_limit_test": BasicEnv(),  # Isolated — corrupts rate limiter state
        "wrong_pw_test": BasicEnv(),   # Isolated — tests wrong password flow
        "lifecycle_test": BasicEnv(),  # Isolated — tests sealed→active→lock→active
        "veracrypt_test": BasicEnv(),  # Isolated — VeraCrypt container creation
        "real_usage_test": BasicEnv(),  # Isolated — full real-usage simulation
        "dead_mans_switch_test": BasicEnv(),  # Isolated — Pi-killed simulation
        "auth_test": BasicEnv(),  # Isolated — admin token tests assert exact device count
        "data_persistence_pi_kill": BasicEnv(),  # Isolated — kills + restarts the server
        "data_persistence_many_files": BasicEnv(),  # Isolated — 50-file round-trip
        "data_persistence_large_file": BasicEnv(),  # Isolated — 50MB round-trip
        "postgres_persistence": BasicEnv(),  # Isolated — postgres in vault
        "sqlite_persistence": BasicEnv(),  # Isolated — sqlite in vault
    }

    # Runtime
    datadir = flexitest.create_datadir_in_workspace(os.path.join(root_dir, "_dd"))
    runtime = flexitest.TestRuntime(global_envs, datadir, factories)

    # Discover tests
    modules = scan_dir_for_modules(test_dir)

    # Filter
    if args.tests or args.tests_pos:
        selected = set(args.tests or []) | set(args.tests_pos or [])
        modules = {k: v for k, v in modules.items() if k in selected}
    elif args.groups:
        groups = set(args.groups)
        modules = {
            k: v for k, v in modules.items()
            if any(g in v for g in groups)
        }

    if not modules:
        print("No tests matched the specified filters.")
        return 1

    tests = load_candidate_modules(modules)
    runtime.prepare_registered_tests()

    # Filter to only tests that were actually registered (some may be
    # conditionally skipped, e.g., VeraCrypt test when not running as root).
    tests = [t for t in tests if t in runtime.test_ictxs]

    if not tests:
        print("No registered tests to run.")
        return 1

    # Run
    results = runtime.run_tests(tests)
    flexitest.dump_results(results)
    flexitest.fail_on_error(results)

    return 0


if __name__ == "__main__":
    sys.exit(main())
