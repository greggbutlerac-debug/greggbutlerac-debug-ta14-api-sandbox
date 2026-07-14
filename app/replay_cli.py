"""
TA-14 Independent Route Replay Standard
Command-line interface for package inspection and verification.

Usage
-----

Verify a replay package:

    python -m app.replay_cli verify route-package.zip

Verify and write a JSON report:

    python -m app.replay_cli verify route-package.zip \
        --report verification-report.json

Inspect archive members without verifying:

    python -m app.replay_cli inspect route-package.zip

Print verifier version:

    python -m app.replay_cli version

Exit codes
----------

0   Package verified successfully.
1   Package was processed but verification failed or was partial.
2   Command usage, file access, archive format, or parsing error.

Security boundary
-----------------
This command verifies the integrity and correspondence of preserved replay
records. It does not independently establish that an external evidence source
was truthful unless that source was authenticated, preserved, and available
for independent review.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

from .replay_models import (
    IndependentVerificationReport,
    VerificationStatus,
)
from .replay_package import (
    ReplayPackageError,
    inspect_package_members,
)
from .replay_verify import (
    ReplayVerificationError,
    verification_summary,
    verify_and_write_report,
    verify_replay_package,
)


CLI_NAME = "ta14-replay"
CLI_VERSION = "1.0.0"
DEFAULT_VERIFIER_NAME = "TA-14 Independent Replay Verifier"


class CLIError(ValueError):
    """Raised when command-line input cannot be handled safely."""


def _existing_file(
    value: str,
) -> Path:
    """Resolve and validate an existing file argument."""

    path = Path(value).expanduser()

    if not path.exists():
        raise argparse.ArgumentTypeError(
            f"File does not exist: {path}"
        )

    if not path.is_file():
        raise argparse.ArgumentTypeError(
            f"Path is not a file: {path}"
        )

    return path


def _output_path(
    value: str,
) -> Path:
    """Resolve an output path without creating it."""

    return Path(value).expanduser()


def _build_parser() -> argparse.ArgumentParser:
    """Create the TA-14 replay command parser."""

    parser = argparse.ArgumentParser(
        prog=CLI_NAME,
        description=(
            "Inspect and independently verify TA-14 route replay packages."
        ),
        epilog=(
            "No admissible evidence. No admissible execution."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"{CLI_NAME} {CLI_VERSION}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    verify_parser = subparsers.add_parser(
        "verify",
        help=(
            "Independently verify a TA-14 replay package."
        ),
        description=(
            "Verify package files, signatures, route identity, "
            "receipt correspondence, ledger integrity, execution, "
            "and outcome records."
        ),
    )

    verify_parser.add_argument(
        "package",
        type=_existing_file,
        help="Path to the TA-14 replay ZIP package.",
    )

    verify_parser.add_argument(
        "--report",
        type=_output_path,
        default=None,
        help=(
            "Optional path for the JSON verification report."
        ),
    )

    verify_parser.add_argument(
        "--summary",
        type=_output_path,
        default=None,
        help=(
            "Optional path for the plain-text verification summary."
        ),
    )

    verify_parser.add_argument(
        "--json",
        action="store_true",
        help=(
            "Print the complete verification report as JSON "
            "instead of the plain-text summary."
        ),
    )

    verify_parser.add_argument(
        "--quiet",
        action="store_true",
        help=(
            "Suppress standard output. Exit status still reports "
            "the verification result."
        ),
    )

    verify_parser.add_argument(
        "--overwrite",
        action="store_true",
        help=(
            "Allow replacement of existing report or summary files."
        ),
    )

    verify_parser.add_argument(
        "--verifier-name",
        default=DEFAULT_VERIFIER_NAME,
        help=(
            "Human-readable verifier name preserved in the report."
        ),
    )

    verify_parser.add_argument(
        "--verifier-version",
        default=CLI_VERSION,
        help=(
            "Verifier implementation version preserved in the report."
        ),
    )

    inspect_parser = subparsers.add_parser(
        "inspect",
        help=(
            "List replay-package members without performing verification."
        ),
        description=(
            "Open the ZIP boundary safely and print its member names. "
            "This command does not validate signatures or record integrity."
        ),
    )

    inspect_parser.add_argument(
        "package",
        type=_existing_file,
        help="Path to the TA-14 replay ZIP package.",
    )

    inspect_parser.add_argument(
        "--json",
        action="store_true",
        help="Print archive members as a JSON array.",
    )

    version_parser = subparsers.add_parser(
        "version",
        help="Print the replay CLI version.",
    )

    version_parser.set_defaults(
        version_command=True
    )

    return parser


def _write_text_output(
    path: Path,
    content: str,
    *,
    overwrite: bool,
) -> None:
    """Write a UTF-8 text file atomically."""

    if path.exists() and not overwrite:
        raise CLIError(
            f"Refusing to overwrite existing file: {path}"
        )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    temporary_path = path.with_name(
        f".{path.name}.tmp"
    )

    temporary_path.write_text(
        content,
        encoding="utf-8",
    )

    temporary_path.replace(path)


def _report_json(
    report: IndependentVerificationReport,
) -> str:
    """Serialize a verification report for terminal output."""

    return (
        json.dumps(
            report.model_dump(
                mode="json"
            ),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _verification_exit_code(
    report: IndependentVerificationReport,
) -> int:
    """Map a verification report status to a process exit code."""

    if (
        report.overall_status
        == VerificationStatus.VERIFIED
        and report.independently_replayable
    ):
        return 0

    return 1


def _run_verify(
    args: argparse.Namespace,
) -> int:
    """Execute the independent package-verification command."""

    package_path: Path = args.package
    report_path: Optional[Path] = args.report
    summary_path: Optional[Path] = args.summary

    if report_path is not None:
        report = verify_and_write_report(
            package_path=package_path,
            report_path=report_path,
            verifier_name=args.verifier_name,
            verifier_version=args.verifier_version,
            overwrite=args.overwrite,
        )
    else:
        report = verify_replay_package(
            package_path,
            verifier_name=args.verifier_name,
            verifier_version=args.verifier_version,
        )

    summary = verification_summary(
        report
    )

    if summary_path is not None:
        _write_text_output(
            summary_path,
            summary,
            overwrite=args.overwrite,
        )

    if not args.quiet:
        if args.json:
            sys.stdout.write(
                _report_json(report)
            )
        else:
            sys.stdout.write(summary)

            if not summary.endswith("\n"):
                sys.stdout.write("\n")

    return _verification_exit_code(
        report
    )


def _run_inspect(
    args: argparse.Namespace,
) -> int:
    """Execute bounded replay-package inspection."""

    members = inspect_package_members(
        args.package
    )

    if args.json:
        sys.stdout.write(
            json.dumps(
                members,
                ensure_ascii=False,
                indent=2,
            )
            + "\n"
        )
    else:
        for member in members:
            sys.stdout.write(
                f"{member}\n"
            )

    return 0


def _run_version() -> int:
    """Print the CLI implementation version."""

    sys.stdout.write(
        f"{CLI_NAME} {CLI_VERSION}\n"
    )

    return 0


def run(
    argv: Optional[Sequence[str]] = None,
) -> int:
    """
    Run the TA-14 replay command.

    This function returns an exit code instead of terminating directly,
    allowing the CLI to be tested without spawning a subprocess.
    """

    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            return _run_verify(args)

        if args.command == "inspect":
            return _run_inspect(args)

        if args.command == "version":
            return _run_version()

        raise CLIError(
            f"Unsupported command: {args.command}"
        )

    except (
        CLIError,
        ReplayPackageError,
        ReplayVerificationError,
        FileNotFoundError,
        PermissionError,
        OSError,
    ) as exc:
        sys.stderr.write(
            f"{CLI_NAME}: error: {exc}\n"
        )

        return 2


def main() -> None:
    """Command-line entry point."""

    raise SystemExit(
        run()
    )


if __name__ == "__main__":
    main()
