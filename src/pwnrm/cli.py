"""
pwnrm.cli — CLI entry point & Dead Reckoning replay dispatcher
"""

import sys
import re
import logging
from pathlib import Path
from datetime import datetime
from impacket import version
from impacket.examples import logger

from .core       import Runspace, create_transport, argument_parser
from .shell      import PwnShell
from .shell.ui   import _BANNER, c, DIM, Y, G, R, BLD


def parse_replay_log(log_path: str) -> list[str]:
    """Extracts executable commands from a PwnRM transcript log."""
    path = Path(log_path)
    if not path.is_file():
        raise FileNotFoundError(f"Replay log not found: {log_path}")
    commands = []
    # Match lines like "PS C:\Users\Admin> whoami" or raw operator inputs
    cmd_re = re.compile(r"^PS\s+[^>]+>\s*(.+)$")
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        m = cmd_re.match(line)
        if m:
            cmd = m.group(1).strip()
            if cmd and not cmd.startswith("exit") and not cmd.startswith("quit"):
                commands.append(cmd)
    return commands


def main():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    print(_BANNER)
    args      = argument_parser().parse_args()
    logger.init(args.ts)
    logging.getLogger().setLevel(logging.DEBUG if args.debug else logging.INFO)
    if args.debug:
        logging.debug(version.getInstallationPath())

    timeout   = int(args.timeout)
    try:
        transport = create_transport(args)
    except Exception as e:
        logging.error("Transport setup failed: %s", e)
        sys.exit(1)

    tinfo = {
        "host": getattr(args, "target", "?"),
        "user": getattr(args, "username", "?"),
    }

    try:
        with Runspace(transport, timeout) as runspace:
            shell = PwnShell(runspace, target_info=tinfo)
            try:
                if args.replay:
                    replayed_cmds = parse_replay_log(args.replay)
                    print(c(Y + BLD, f"\n  [⚡] Dead Reckoning Replay: executing {len(replayed_cmds)} commands from {args.replay}...\n"))
                    shell.repl(iter(replayed_cmds))
                    print(c(G + BLD, f"\n  [+] Replay sequence completed. Entering interactive session.\n"))
                    shell.repl()
                elif args.X:
                    shell.repl(iter([args.X]))
                else:
                    shell.help()
                    shell.repl()
            except EOFError:
                pass
            finally:
                elapsed = str(datetime.now() - shell.start_time).split(".")[0]
                print(c(DIM, f"\n[~] Session duration: {elapsed}  |  Commands: {shell.cmd_count}\n"))
    except Exception as e:
        logging.error("Connection failed: %s", e)


if __name__ == "__main__":
    main()