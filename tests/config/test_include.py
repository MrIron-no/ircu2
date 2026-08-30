"""Configuration file inclusion and the hand-coded lexer (commits 66304e0,
844238f, e50a5c3).

Each case writes a small configuration into the hub container and runs
``ircd -k`` (check configuration and exit).  ``-c user@ip`` prints the
Client block that would be attached, which proves blocks from an included
file were loaded.
"""

from __future__ import annotations

import subprocess

import pytest

from conftest import docker_cp_text, docker_exec

pytestmark = pytest.mark.single_server

TMP = "/opt/ircu/tmp"

BASE = """\
General { name = "check.test.net"; description = "check"; numeric = 9; };
Admin { Location = "Test"; Contact = "test@test.net"; };
Class { name = "Local"; pingfreq = 90 seconds; sendq = 160000; maxlinks = 10; };
%(extra)s
Port { port = 6999; };
"""


def _check(container, name, files, client=None):
    # ircd refuses to run as root; the container's exec default is root.
    docker_exec(container, "sh", "-c", f"mkdir -p {TMP} && chmod 777 {TMP}")
    for fname, text in files.items():
        docker_cp_text(container, f"{TMP}/{fname}", text)
    cmd = ["timeout", "-s", "KILL", "15", "/opt/ircu/bin/ircd", "-k", "-d", TMP, "-f", f"{TMP}/{name}"]
    if client:
        cmd += ["-c", client]
    return docker_exec(container, *cmd, timeout=30, user="ircu")


def _ok(result: subprocess.CompletedProcess):
    return result.returncode == 0 and "checked okay" in result.stderr


async def test_plain_config_checks_okay(ircd_hub):
    files = {"plain.conf": BASE % {"extra": 'Client { ip = "*"; class = "Local"; };'}}
    result = _check(ircd_hub["container"], "plain.conf", files)
    assert _ok(result), result


async def test_included_file_is_loaded(ircd_hub):
    files = {
        "inc_main.conf": BASE % {"extra": 'Include "inc_extra.conf";'},
        "inc_extra.conf": '# included\nClient { ip = "*"; class = "Local"; };\n',
    }
    result = _check(ircd_hub["container"], "inc_main.conf", files, client="probe@10.55.0.1")
    assert _ok(result), result
    assert "Match!" in result.stdout + result.stderr, result
    assert "class=Local" in result.stdout + result.stderr, result


async def test_nested_include(ircd_hub):
    files = {
        "nest_main.conf": BASE % {"extra": 'Include "nest_mid.conf";'},
        "nest_mid.conf": 'Class { name = "Nested"; pingfreq = 90 seconds; sendq = 1000; maxlinks = 5; };\n'
                         'include "nest_leaf.conf";\n',
        "nest_leaf.conf": 'Client { ip = "*"; class = "Nested"; };\n',
    }
    result = _check(ircd_hub["container"], "nest_main.conf", files, client="probe@10.55.0.1")
    assert _ok(result), result
    assert "class=Nested" in result.stdout + result.stderr, result


async def test_include_keyword_is_case_insensitive(ircd_hub):
    files = {
        "case_main.conf": BASE % {"extra": 'INCLUDE "case_extra.conf";'},
        "case_extra.conf": 'Client { ip = "*"; class = "Local"; };\n',
    }
    result = _check(ircd_hub["container"], "case_main.conf", files, client="probe@10.55.0.1")
    assert _ok(result), result
    assert "Match!" in result.stdout + result.stderr, result


async def test_syntax_error_in_included_file_is_reported(ircd_hub):
    files = {
        "bad_main.conf": BASE % {"extra": 'Include "bad_extra.conf";'},
        "bad_extra.conf": 'Client { ip = "*" class = "Local"; };\n',  # missing ';'
    }
    result = _check(ircd_hub["container"], "bad_main.conf", files)
    assert result.returncode not in (0, 137), result
    assert "bad_extra.conf" in result.stderr, result.stderr


async def test_missing_include_file_is_reported(ircd_hub):
    files = {"miss_main.conf": BASE % {"extra": 'Include "does_not_exist.conf";'}}
    result = _check(ircd_hub["container"], "miss_main.conf", files)
    assert result.returncode != 0, result
    assert "error opening file" in result.stderr, result.stderr


@pytest.mark.xfail(
    reason="ircd never exits after failing to open an Include file (killed by timeout)",
    strict=True,
)
async def test_missing_include_file_exits_promptly(ircd_hub):
    files = {"miss2_main.conf": BASE % {"extra": 'Include "does_not_exist.conf";'}}
    result = _check(ircd_hub["container"], "miss2_main.conf", files)
    assert result.returncode != 137, "ircd hung and was killed by timeout"


async def test_include_restricted_to_block_types(ircd_hub):
    files = {
        "types_main.conf": BASE % {"extra": 'Include Client from "types_extra.conf";'},
        "types_extra.conf": 'Client { ip = "*"; class = "Local"; };\n',
    }
    result = _check(ircd_hub["container"], "types_main.conf", files, client="probe@10.55.0.1")
    assert _ok(result), result


async def test_hash_comments_and_quoted_strings(ircd_hub):
    files = {
        "lex.conf": BASE % {"extra": (
            '# a comment line\n'
            'Client { ip = "*"; class = "Local"; }; # trailing comment\n'
            '   # indented comment with "quotes" and ; braces {}\n'
            'Features { "MOTD_BANNER" = "hash # inside quotes is not a comment"; };\n'
        )},
    }
    result = _check(ircd_hub["container"], "lex.conf", files)
    assert _ok(result), result


@pytest.mark.xfail(
    reason="the grammar requires at least one block per included file, so an empty/comment-only include is a syntax error",
    strict=True,
)
async def test_include_of_empty_and_comment_only_file(ircd_hub):
    files = {
        "empty_main.conf": BASE % {"extra": 'Client { ip = "*"; class = "Local"; };\nInclude "empty_extra.conf";'},
        "empty_extra.conf": "# nothing here\n\n",
    }
    result = _check(ircd_hub["container"], "empty_main.conf", files)
    assert _ok(result), result


@pytest.mark.xfail(
    reason="a self-including file aborts ircd (SIGABRT after 'memory exhausted' from the parser)",
    strict=True,
)
async def test_include_cycle_is_not_fatal(ircd_hub):
    """A file that includes itself must not make ircd loop or crash."""
    files = {
        "cycle_main.conf": BASE % {"extra": 'Client { ip = "*"; class = "Local"; };\nInclude "cycle_self.conf";'},
        "cycle_self.conf": 'Include "cycle_self.conf";\n',
    }
    result = _check(ircd_hub["container"], "cycle_main.conf", files)
    assert result.returncode != 137, "ircd hung on a self-including file"
    assert result.returncode != 134, f"ircd aborted on a self-including file: {result.stderr[-200:]}"
    assert result.returncode != 0


async def test_include_relative_to_dpath(ircd_hub):
    """Include paths are resolved relative to the working directory (-d)."""
    files = {
        "rel_main.conf": BASE % {"extra": 'Include "sub/rel_extra.conf";'},
    }
    docker_exec(ircd_hub["container"], "sh", "-c", f"mkdir -p {TMP}/sub && chmod 777 {TMP} {TMP}/sub")
    docker_cp_text(ircd_hub["container"], f"{TMP}/sub/rel_extra.conf",
                   'Client { ip = "*"; class = "Local"; };\n')
    result = _check(ircd_hub["container"], "rel_main.conf", files, client="probe@10.55.0.1")
    assert _ok(result), result
    assert "Match!" in result.stdout + result.stderr


async def test_include_restricted_block_type_refused(ircd_hub):
    """A block outside the listed types in "Include <types> from" is an error."""
    files = {
        "types2_main.conf": BASE % {"extra": 'Client { ip = "*"; class = "Local"; };\nInclude Class from "types2_extra.conf";'},
        "types2_extra.conf": 'Client { ip = "*"; class = "Local"; };\n',
    }
    result = _check(ircd_hub["container"], "types2_main.conf", files)
    assert result.returncode != 0, result
    assert "forbidden" in result.stderr, result.stderr
