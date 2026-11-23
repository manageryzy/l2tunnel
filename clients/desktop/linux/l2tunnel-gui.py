#!/usr/bin/env python3
"""Control an existing Common service using the same l2tunnelctl as the CLI."""
import argparse
import json
from pathlib import Path
import queue
import shutil
import subprocess
import threading
import tkinter as tk
from tkinter import ttk


def fetch(ctl, path, command):
    result = subprocess.run(
        [ctl, command, '--api-version', '4', '--control-socket', path],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=70, check=False,
    )
    if not 0 < len(result.stdout) <= 32769:
        raise ValueError('Service unavailable')
    reply = json.loads(result.stdout)
    if reply.get('version') != 4 or type(reply.get('ok')) is not bool:
        raise ValueError('Incompatible service')
    return reply


def projection(reply):
    state = reply.get('state') or {}
    common = state.get('common') or {}
    phase = state.get('phase', 'Unavailable')
    running = (phase == 'forwarding' and common.get('running') is True
               and not common.get('terminal') and not common.get('service_terminal'))
    rows = [phase, '—', '—', '—', '—', '—']
    if running:
        carrier = common.get('carrier')
        raw = common.get('raw_carrier') or {}
        original = common.get('original_carrier') or {}
        maintained = (common.get('maintained_carrier') or {}).get('effective') or {}
        if raw or original or maintained:
            rows[1] = raw.get('effective') or original.get('effective') or maintained.get('carrier') or carrier
            rows[2] = raw.get('inner_cover') or original.get('udp_cover') or '—'
        elif carrier in {'quic-like', 'media-like'}:
            rows[1], rows[2] = 'UDP', carrier
        else:
            rows[1] = carrier
        rows[3:] = [common.get('peer'), common.get('algorithm'), state.get('epoch')]
    return [str(value)[:128] if value is not None else '—' for value in rows], running


class Window:
    def __init__(self, root, path, ctl):
        self.root, self.ctl = root, ctl
        self.replies = queue.Queue(maxsize=1)
        self.pending = False
        self.running = self.available = False
        root.title('l2tunnel')
        frame = ttk.Frame(root, padding=22)
        frame.grid(sticky='nsew')
        root.columnconfigure(0, weight=1)
        frame.columnconfigure(1, weight=1)
        self.path = tk.StringVar(value=path)
        ttk.Label(frame, text='Service socket').grid(row=0, column=0, sticky='w', padx=(0, 14))
        self.entry = ttk.Entry(frame, textvariable=self.path, width=42)
        self.entry.grid(row=0, column=1, sticky='ew')
        self.entry.bind('<Return>', lambda _: self.submit('status'))
        self.refresh = ttk.Button(frame, text='Refresh', command=lambda: self.submit('status'))
        self.refresh.grid(row=0, column=2, padx=(8, 0))
        self.values = []
        for index, label in enumerate(('State', 'Outer carrier', 'UDP cover', 'Peer', 'Algorithm', 'Epoch'), 1):
            ttk.Label(frame, text=label).grid(row=index, column=0, sticky='w', pady=(10, 0))
            value = tk.StringVar(value='—')
            ttk.Label(frame, textvariable=value).grid(row=index, column=1, columnspan=2, sticky='w', pady=(10, 0))
            self.values.append(value)
        controls = ttk.Frame(frame)
        controls.grid(row=7, column=0, columnspan=3, sticky='w', pady=(18, 0))
        self.connect = ttk.Button(controls, text='Connect', command=lambda: self.submit('reconnect'))
        self.disconnect = ttk.Button(controls, text='Disconnect', command=lambda: self.submit('disconnect'))
        self.connect.pack(side='left')
        self.disconnect.pack(side='left', padx=8)
        self.notice = tk.StringVar()
        ttk.Label(frame, textvariable=self.notice).grid(row=8, column=0, columnspan=3, sticky='w', pady=(8, 0))
        self.path.trace_add('write', self.changed)
        self.changed()
        if path:
            self.submit('status')
        root.after(100, self.poll)

    def changed(self, *_):
        self.available = self.running = False
        for value in self.values:
            value.set('—')
        self.notice.set('')
        self.buttons()

    def buttons(self):
        self.entry.configure(state='disabled' if self.pending else 'normal')
        self.refresh.configure(state='normal' if not self.pending and self.path.get() else 'disabled')
        self.connect.configure(text='Reconnect' if self.running else 'Connect',
                               state='normal' if self.available and not self.pending else 'disabled')
        self.disconnect.configure(state='normal' if self.running and not self.pending else 'disabled')

    def submit(self, command):
        path = self.path.get()
        if self.pending or not path:
            return
        self.pending = True
        self.notice.set('Waiting for the service…')
        self.buttons()

        def request():
            try:
                reply = fetch(self.ctl, path, command)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                reply = {'ok': False, 'code': 'Service unavailable or timed out'}
            self.replies.put(reply)

        threading.Thread(target=request, daemon=True).start()

    def poll(self):
        try:
            reply = self.replies.get_nowait()
        except queue.Empty:
            pass
        else:
            rows, self.running = projection(reply)
            self.available = rows[0] in {'disconnected', 'forwarding', 'failed'}
            for value, observed in zip(self.values, rows):
                value.set(observed)
            self.notice.set('' if reply['ok'] else str(reply.get('code', 'Request failed'))[:128])
            self.pending = False
            self.buttons()
        self.root.after(100, self.poll)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', default='')
    sibling = Path(__file__).resolve().with_name('l2tunnelctl')
    parser.add_argument('--ctl', default=str(sibling) if sibling.is_file() else shutil.which('l2tunnelctl') or 'l2tunnelctl')
    args = parser.parse_args()
    window = tk.Tk()
    Window(window, args.socket, args.ctl)
    window.mainloop()
