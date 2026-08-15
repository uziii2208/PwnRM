"""
shell.ctrlc — Graceful Ctrl+C handling
"""

from signal import SIGINT, signal, getsignal
from .ui import c, Y, DIM


class CtrlCHandler:
    def __init__(self, max_interrupts=4, timeout=5):
        self.max_interrupts = max_interrupts
        self.timeout        = timeout

    def __enter__(self):
        self.interrupted      = 0
        self.released         = False
        self.original_handler = getsignal(SIGINT)

        def handler(signum, frame):
            self.interrupted += 1
            if self.interrupted > 1:
                n = self.max_interrupts - self.interrupted + 2
                print()
                print(c(Y, f"  [!] Ctrl+C spam detected — {n} more will force-terminate."))
                print(c(DIM, f"      Wait ~{self.timeout}s for the remote session to receive the interrupt."))
            if self.interrupted > self.max_interrupts:
                self.release()

        signal(SIGINT, handler)
        return self

    def __exit__(self, *_):
        self.release()

    def release(self):
        if self.released:
            return False
        signal(SIGINT, self.original_handler)
        self.released = True
        return True