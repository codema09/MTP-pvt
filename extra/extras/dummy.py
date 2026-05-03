#!/usr/bin/env python3
import sys
import signal
import time

class Dummy:
    def __init__(self):
        self.inputs_given = 0

    def run(self):
        def _print_summary():
            # EXACT same logic used in the USC program where a summary function
            # prints out the total count when SIGINT or KeyboardInterrupt happens
            print(f"\nTotal inputs given: {self.inputs_given}")
            sys.stdout.flush()

        # Same lambda logic for signals
        signal.signal(signal.SIGTERM, lambda *_: (_print_summary(), sys.exit(0)))
        signal.signal(signal.SIGINT, lambda *_: (_print_summary(), sys.exit(0)))

        while True:
            try:
                _ = input("input: ")
                self.inputs_given += 1
            except KeyboardInterrupt:
                _print_summary()
                break
            except EOFError:
                # To handle ctrl+d as well
                _print_summary()
                break

if __name__ == "__main__":
    dummy = Dummy()
    dummy.run()
