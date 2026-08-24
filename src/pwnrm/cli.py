"""
pwnrm.cli — CLI entry point
"""

import sys
import logging
from datetime import datetime
from impacket import version
from impacket.examples import logger

from .core       import Runspace, create_transport, argument_parser
from .shell      import PwnShell
from .shell.ui   import _BANNER, c, DIM


def main():
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
                if args.X:
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