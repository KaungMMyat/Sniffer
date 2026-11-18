"""Record the full packet stream with Wireshark's ``dumpcap``.

The live view parses packets in Python and can fall behind on fast links.
dumpcap writes at capture speed, independently of the UI, so the recording
stays complete even when the table is busy.
"""

import os
import shutil
import signal
import subprocess
import sys

_DUMPCAP_PATHS = (
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
)


def find_dumpcap():
    found = shutil.which("dumpcap")
    if found:
        return found
    for path in _DUMPCAP_PATHS:
        if os.path.isfile(path):
            return path
    return None


class DumpcapRecorder:
    def __init__(self, interface, output_path, bpf_filter=None):
        self.interface = interface
        self.output_path = output_path
        self.bpf_filter = bpf_filter
        self.process = None

    @property
    def is_running(self):
        return self.process is not None and self.process.poll() is None

    def start(self):
        dumpcap = find_dumpcap()
        if dumpcap is None:
            raise RuntimeError(
                "dumpcap not found. Install Wireshark to record traffic."
            )
        os.makedirs(os.path.dirname(self.output_path) or ".", exist_ok=True)

        command = [dumpcap, "-i", self.interface, "-w", self.output_path, "-q"]
        if self.bpf_filter:
            command += ["-f", self.bpf_filter]

        flags = (
            getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            if sys.platform == "win32" else 0
        )
        self.process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=flags,
        )

    def stop(self):
        process = self.process
        self.process = None
        if process is None or process.poll() is not None:
            return
        try:
            if sys.platform == "win32":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
                process.wait(timeout=5)
            except Exception:
                pass
