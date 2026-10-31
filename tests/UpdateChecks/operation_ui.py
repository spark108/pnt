"""Exercise the real shell watcher in a PTY, without installing anything."""
import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import tempfile
import termios
import time

repo = Path(__file__).resolve().parents[2]
watch = re.search(r'(?ms)^watch_operation\(\) \{.*?^\}', (repo / 'pnt.sh').read_text()).group()
with tempfile.TemporaryDirectory(prefix='pnt-tui-') as folder:
    folder = Path(folder)
    runner = folder / 'watch.sh'
    runner.write_text(f"SCRIPT_DIR='{repo}'\nOPERATIONS='{folder}'\nsystemctl() {{ return 0; }}\n" + watch + '\nwatch_operation test\n')
    writer = folder / 'writer.sh'
    writer.write_text(f"cd '{folder}'\nprintf '10\\nInstalling packages\\n' > test.stage\n"
                      "i=0;while [ $i -lt 55 ]; do echo package-$i >> test.log;i=$((i+1));done\n"
                      "sleep 0.4\nprintf '60\\nBuilding PNT\\n' > test.stage\necho compiler-live >> test.log\n"
                      "sleep 0.8\necho 7 > test.result\n")
    for terminal in (False, True):
        for name in ('test.stage', 'test.log', 'test.result'):
            (folder / name).unlink(missing_ok=True)
        producer = subprocess.Popen(['sh', str(writer)])
        if terminal:
            pid, master = pty.fork()
            if pid == 0:
                os.environ['TERM'] = 'xterm-256color'
                os.execvp('sh', ['sh', str(runner)])
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            output = bytearray()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if select.select([master], [], [], .2)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 30, 100, 0, 0))
            else:
                os.kill(pid, signal.SIGKILL)
                raise AssertionError('Watcher hung')
            _, status = os.waitpid(pid, 0)
            os.close(master)
            assert os.waitstatus_to_exitcode(status) == 7
            text = output.decode()
            assert '\x1b[?1049h' in text and '\x1b[1;28r' in text, 'No full screen / resize support'
            assert '\x1b[29;1H' in text and '\x1b[30;1H' in text, 'Footer not pinned'
            assert '\x1b[r\x1b[?25h\x1b[?1049l' in text, 'Terminal not restored'
        else:
            result = subprocess.run(['sh', str(runner)], capture_output=True, timeout=8)
            assert result.returncode == 7
            text = result.stdout.decode()
            assert not result.stderr, result.stderr.decode()
            assert '\x1b' not in text
        producer.wait(timeout=3)
        assert 'package-0' in text and 'package-54' in text and 'compiler-live' in text, f'Missing live log output (terminal={terminal}): {text!r}'
        assert 'Building PNT' in text
    for name in ('test.stage', 'test.log', 'test.result'):
        (folder / name).unlink(missing_ok=True)
    producer = subprocess.Popen(['sh', str(writer)])
    pid, master = pty.fork()
    if pid == 0:
        os.environ['TERM'] = 'xterm-256color'
        os.execvp('sh', ['sh', str(runner)])
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
    output = bytearray()
    interrupted = False
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if select.select([master], [], [], .1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                break
            if not chunk:
                break
            output.extend(chunk)
            if not interrupted and b'package-0' in output:
                os.write(master, b'\x03')
                interrupted = True
    else:
        os.kill(pid, signal.SIGKILL)
        raise AssertionError('Ctrl+C did not detach the viewer')
    _, status = os.waitpid(pid, 0)
    os.close(master)
    assert interrupted and os.waitstatus_to_exitcode(status) == 130
    assert b'\x1b[r\x1b[?25h\x1b[?1049l' in output
    producer.wait(timeout=3)
    assert (folder / 'test.result').read_text().strip() == '7', 'Viewer cancellation killed the worker'
print('PASS: PTY full screen, live logs, fixed footer, resize/restoration, Ctrl+C detaches without cancelling worker, plain output and worker exit code.')
