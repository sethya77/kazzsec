#!/usr/bin/env python3
"""
Enhanced Monitor - Full Edition (GUI + Adaptive scanning + Throttling + Web Dashboard + Packaging notes)

Features:
- Alert throttling / deduplication (configurable per target/port)
- Adaptive scanning (stability-based backoff / accelerate)
- Optional built-in Flask dashboard (start_web button) - requires Flask
- Tkinter GUI for local control; can save logs/CSV
- Minimal external deps: requests (alerts). Flask is optional.

Usage:
    python monitor_full.py

Optional: pip install requests flask pyinstaller pywin32
"""

import threading, socket, time, ipaddress, csv, datetime, queue, sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import smtplib, ssl
import requests
from collections import defaultdict, deque

# Optional Flask
try:
    from flask import Flask, jsonify, render_template_string
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

# ----------------- Config defaults -----------------
ALERT_MIN_INTERVAL = 300  # seconds between external alerts for same (target,port,proto)
STABILITY_THRESHOLD = 3   # number of identical observations before backoff (stable)
MIN_INTERVAL = 5          # seconds minimum per-item interval
MAX_INTERVAL = 3600       # seconds maximum per-item interval

# ----------------- Utilities -----------------

def expand_targets(text):
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if '/' in line:
            try:
                net = ipaddress.ip_network(line, strict=False)
                for ip in net.hosts():
                    results.append(str(ip))
                continue
            except Exception:
                pass
        results.append(line)
    return results

def parse_ports(text):
    ports = set()
    for part in text.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            try:
                a,b = part.split('-',1); a=int(a); b=int(b)
                for p in range(max(1,a), min(65535,b)+1):
                    ports.add(p)
            except:
                continue
        else:
            try:
                ports.add(int(part))
            except:
                continue
    return sorted(p for p in ports if 1 <= p <= 65535)

def tcp_check(target, port, timeout=1.0, grab_banner=False):
    try:
        addr = socket.gethostbyname(target)
    except Exception as e:
        return False, f"DNS error: {e}", None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((addr, port))
        banner = None
        if grab_banner:
            try:
                s.settimeout(1.5)
                banner = s.recv(1024)
                if banner:
                    banner = banner.decode(errors='replace').strip()
            except:
                banner = None
        s.close()
        return True, None, banner
    except socket.timeout:
        return False, None, None
    except Exception as e:
        return False, str(e), None

def udp_probe(target, port, timeout=1.0):
    try:
        addr = socket.gethostbyname(target)
    except Exception as e:
        return False, f"DNS error: {e}"
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(b'\x00', (addr, port))
        data, _ = s.recvfrom(1024)
        s.close()
        return True, data.decode(errors='replace')
    except socket.timeout:
        return False, None
    except Exception as e:
        return False, str(e)

# ----------------- Alert senders -----------------

def send_telegram(bot_token, chat_id, message):
    try:
        url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        r = requests.post(url, data={"chat_id": chat_id, "text": message}, timeout=10)
        return r.status_code == 200, r.text
    except Exception as e:
        return False, str(e)

def send_discord(webhook_url, message):
    try:
        r = requests.post(webhook_url, json={"content": message}, timeout=10)
        return r.status_code in (200,204), r.text
    except Exception as e:
        return False, str(e)

def send_email(smtp_server, smtp_port, username, password, recipient, subject, body):
    try:
        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as server:
            server.starttls(context=context)
            server.login(username, password)
            msg = f"Subject: {subject}\n\n{body}"
            server.sendmail(username, recipient, msg)
        return True, "sent"
    except Exception as e:
        return False, str(e)

# ----------------- Adaptive monitor (throttling + adaptive intervals) -----------------

class AdaptiveMonitor:
    def __init__(self, targets, ports, base_interval, timeout, workers,
                 udp=False, banner=False, alert_cfg=None, event_q=None):
        self.targets = targets
        self.ports = ports
        self.base_interval = max(1, base_interval)
        self.timeout = timeout
        self.workers = max(1, workers)
        self.udp = udp
        self.banner = banner
        self.alert_cfg = alert_cfg or {}
        self.event_q = event_q or queue.Queue()
        self.stop_event = threading.Event()

        self.state = {}  # (t,p,proto) -> bool
        self.last_alert_at = {}  # throttling timestamps
        self.stability = defaultdict(lambda: deque(maxlen=STABILITY_THRESHOLD))
        self.adaptive_interval = defaultdict(lambda: self.base_interval)
        self.last_run_map = {}
        self.recent_alerts = deque(maxlen=500)

    def start(self):
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if hasattr(self, 'thread'):
            self.thread.join(timeout=5)

    def run(self):
        self.event_q.put(("info", f"Adaptive baseline scan: {len(self.targets)}x{len(self.ports)} udp={self.udp}"))
        # baseline
        self._scan_all(report_new=False)
        while not self.stop_event.is_set():
            self.scan_once()
            time.sleep(0.1)

    def _scan_all(self, report_new=True):
        futures = []
        with ThreadPoolExecutor(max_workers=self.workers) as ex:
            for t in self.targets:
                for p in self.ports:
                    proto = 'udp' if self.udp else 'tcp'
                    key = (t,p,proto)
                    now = time.time()
                    interval = self.adaptive_interval.get(key, self.base_interval)
                    last = self.last_run_map.get(key, 0)
                    if now - last < interval:
                        continue
                    self.last_run_map[key] = now
                    if self.udp:
                        futures.append(ex.submit(self._check_udp, t, p))
                    else:
                        futures.append(ex.submit(self._check_tcp, t, p))
            for fut in as_completed(futures):
                try:
                    key, is_open, info = fut.result()
                except Exception:
                    continue
                prev = self.state.get(key)
                dq = self.stability[key]
                dq.append(is_open)
                stable = len(dq) == dq.maxlen and all(x == dq[0] for x in dq)
                if stable:
                    self.adaptive_interval[key] = min(MAX_INTERVAL,
                                                     max(self.base_interval,
                                                         int(self.adaptive_interval.get(key, self.base_interval) * 2)))
                else:
                    self.adaptive_interval[key] = max(MIN_INTERVAL,
                                                      int(self.adaptive_interval.get(key, self.base_interval) / 2))

                if prev is None:
                    self.state[key] = is_open
                    if is_open and report_new:
                        self._alert_change(key, "OPEN", info)
                else:
                    if is_open and not prev:
                        self.state[key] = True
                        self._alert_change(key, "OPENED", info)
                    elif not is_open and prev:
                        self.state[key] = False
                        self._alert_change(key, "CLOSED", info)

    def scan_once(self):
        self._scan_all(report_new=True)
        self.event_q.put(("cycle", datetime.datetime.utcnow().isoformat() + 'Z'))

    def _check_tcp(self, t, p):
        ok, err, banner = tcp_check(t, p, timeout=self.timeout, grab_banner=self.banner)
        key = (t, p, 'tcp')
        info = err or banner
        return key, ok, info

    def _check_udp(self, t, p):
        ok, info = udp_probe(t, p, timeout=self.timeout)
        key = (t, p, 'udp')
        return key, ok, info

    def _alert_change(self, key, status, info=None):
        t,p,proto = key
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        msg = f"[{ts}] {t}:{p}/{proto} => {status}" + (f" ({info})" if info else "")
        self.event_q.put(("alert", msg))
        self.recent_alerts.appendleft({"ts": ts, "target": t, "port": p, "proto": proto, "status": status, "info": info})

        now = time.time()
        last = self.last_alert_at.get(key, 0)
        min_interval = self.alert_cfg.get('min_alert_interval', ALERT_MIN_INTERVAL)
        if now - last < min_interval:
            # throttled
            self.event_q.put(("info", f"Alert throttled for {t}:{p}/{proto} ({int(now-last)}s since last)"))
            return
        self.last_alert_at[key] = now

        cfg = self.alert_cfg or {}
        try:
            if cfg.get('telegram_token') and cfg.get('telegram_chat_id'):
                send_telegram(cfg['telegram_token'], cfg['telegram_chat_id'], msg)
            if cfg.get('discord_webhook'):
                send_discord(cfg['discord_webhook'], msg)
            if cfg.get('smtp_server') and cfg.get('smtp_user') and cfg.get('smtp_pass') and cfg.get('email_to'):
                send_email(cfg['smtp_server'], cfg['smtp_port'], cfg['smtp_user'], cfg['smtp_pass'], cfg['email_to'],
                           "Network Monitor Alert", msg)
        except Exception as e:
            self.event_q.put(("info", f"Alert send error: {e}"))

# ----------------- Simple Flask dashboard (optional) -----------------
FLASK_HTML = '''<!doctype html><title>Monitor Dashboard</title>
<h2>Monitor Dashboard - Recent Alerts</h2>
<div id="alerts"></div>
<script>
async function loadAlerts(){ let r=await fetch('/alerts'); let j=await r.json(); let html=''; for(let a of j){ html += `<div><b>${a.ts}</b> ${a.target}:${a.port}/${a.proto} => ${a.status} ${a.info?('('+a.info+')'):''}</div>`;} document.getElementById('alerts').innerHTML = html;}
setInterval(loadAlerts,2000); loadAlerts();
</script>
'''

def start_flask_dashboard(monitor, host='127.0.0.1', port=5000):
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not installed. Run: pip install flask")
    app = Flask('monitor_dashboard')
    @app.route('/alerts')
    def alerts():
        # return list of dicts
        return jsonify(list(monitor.recent_alerts)[:200])
    @app.route('/')
    def index():
        return render_template_string(FLASK_HTML)
    thr = threading.Thread(target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False), daemon=True)
    thr.start()
    return thr

# ----------------- GUI -----------------

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Monitor - Full Edition")
        self.root.geometry('1100x750')
        self.event_q = queue.Queue()
        self.monitor = None
        self.web_thread = None
        self.log_file = None
        self.csv_file = None
        self.setup_ui()
        self.root.after(300, self.process_events)

    def setup_ui(self):
        top = ttk.Frame(self.root, padding=6); top.pack(fill='x')
        left = ttk.Frame(top); left.pack(side='left', fill='both', expand=True)
        ttk.Label(left, text='Targets (one per line, CIDR OK):').pack(anchor='w')
        self.targets_txt = scrolledtext.ScrolledText(left, height=6); self.targets_txt.pack(fill='x', pady=4)
        ttk.Label(left, text='Ports (csv, ranges allowed):').pack(anchor='w')
        self.ports_entry = ttk.Entry(left); self.ports_entry.pack(fill='x'); self.ports_entry.insert(0,'22,80,443')
        conf = ttk.Frame(left); conf.pack(fill='x', pady=4)
        ttk.Label(conf, text='Base Interval(s)').pack(side='left'); self.interval_spin = ttk.Spinbox(conf, from_=1,to=86400,width=8); self.interval_spin.pack(side='left', padx=4); self.interval_spin.delete(0,'end'); self.interval_spin.insert(0,'60')
        ttk.Label(conf, text='Timeout(s)').pack(side='left'); self.timeout_entry = ttk.Spinbox(conf, from_=1,to=30,width=6); self.timeout_entry.pack(side='left', padx=4); self.timeout_entry.delete(0,'end'); self.timeout_entry.insert(0,'1')
        ttk.Label(conf, text='Workers').pack(side='left'); self.workers_spin = ttk.Spinbox(conf, from_=1,to=200,width=6); self.workers_spin.pack(side='left', padx=4); self.workers_spin.delete(0,'end'); self.workers_spin.insert(0,'50')
        checks = ttk.Frame(left); checks.pack(fill='x', pady=6)
        self.udp_var = tk.BooleanVar(value=False); ttk.Checkbutton(checks, text='UDP scan', variable=self.udp_var).pack(side='left')
        self.banner_var = tk.BooleanVar(value=False); ttk.Checkbutton(checks, text='Banner grab (TCP)', variable=self.banner_var).pack(side='left', padx=6)
        btns = ttk.Frame(left); btns.pack(fill='x', pady=6)
        self.start_btn = ttk.Button(btns, text='Start Monitor', command=self.start); self.start_btn.pack(side='left')
        self.stop_btn = ttk.Button(btns, text='Stop Monitor', command=self.stop, state='disabled'); self.stop_btn.pack(side='left', padx=6)
        ttk.Button(btns, text='Save log', command=self.save_log).pack(side='left', padx=6)
        ttk.Button(btns, text='Export CSV', command=self.export_csv).pack(side='left')
        ttk.Button(btns, text='Start Web Dashboard', command=self.start_web).pack(side='left', padx=6)
        ttk.Button(btns, text='Stop Web Dashboard', command=self.stop_web).pack(side='left', padx=6)

        right = ttk.Frame(top); right.pack(side='right', fill='both', expand=True)
        ttk.Label(right, text='Alerts / Activity:').pack(anchor='w')
        self.log_box = scrolledtext.ScrolledText(right, height=20, state='disabled'); self.log_box.pack(fill='both', expand=True, padx=4, pady=4)
        bottom = ttk.Frame(self.root, padding=6); bottom.pack(fill='both', expand=True)
        ttk.Label(bottom, text='Detected Open Ports / Banners:').pack(anchor='w')
        self.tree = ttk.Treeview(bottom, columns=('ip','port','proto','status','banner'), show='headings')
        for c in ('ip','port','proto','status','banner'): self.tree.heading(c, text=c.upper())
        self.tree.pack(fill='both', expand=True, padx=4, pady=4)

    def start(self):
        raw = self.targets_txt.get('1.0','end').strip()
        if not raw:
            messagebox.showerror('Error','Enter targets'); return
        targets = expand_targets(raw)
        ports = parse_ports(self.ports_entry.get())
        if not ports:
            messagebox.showerror('Error','Enter ports'); return
        try:
            base_interval = int(self.interval_spin.get()); timeout = float(self.timeout_entry.get()); workers = int(self.workers_spin.get())
        except:
            base_interval=60; timeout=1; workers=50
        udp = self.udp_var.get(); banner = self.banner_var.get()
        alert_cfg = {'min_alert_interval': ALERT_MIN_INTERVAL}
        self.monitor = AdaptiveMonitor(targets, ports, base_interval, timeout, workers, udp=udp, banner=banner, alert_cfg=alert_cfg, event_q=self.event_q)
        self.monitor.start()
        self.start_btn.config(state='disabled'); self.stop_btn.config(state='normal')
        self.log(f"Adaptive monitor started. targets={len(targets)} ports={len(ports)} udp={udp} workers={workers}")

    def stop(self):
        if self.monitor:
            self.monitor.stop()
        self.start_btn.config(state='normal'); self.stop_btn.config(state='disabled')
        self.log("Stop requested.")

    def process_events(self):
        try:
            while True:
                typ, data = self.event_q.get_nowait()
                if typ == 'alert':
                    self.log(data)
                    parts = data.split()
                    token = None
                    for p in parts:
                        if ':' in p and '/' in p:
                            token = p.strip().strip('[],')
                            break
                        elif ':' in p and p.count(':') == 1:
                            token = p.strip().strip('[],')
                            break
                    if token:
                        token = token.replace(']','')
                        if '/' in token:
                            ipport,proto = token.split('/'); ip,port = ipport.split(':')
                        else:
                            ip,port='?','?'; proto='?'
                        self.tree.insert('',0, values=(ip,port,proto,'OPEN',data))
                elif typ == 'info':
                    self.log('[INFO] ' + data)
                elif typ == 'cycle':
                    self.log('[CYCLE] ' + data)
        except queue.Empty:
            pass
        self.root.after(300, self.process_events)

    def log(self, text):
        ts = datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
        line = f"[{ts}] {text}\n"
        self.log_box.configure(state='normal'); self.log_box.insert('end', line); self.log_box.see('end'); self.log_box.configure(state='disabled')
        if self.log_file:
            with open(self.log_file,'a',encoding='utf-8') as f: f.write(line)
        if self.csv_file:
            try:
                with open(self.csv_file,'a',newline='',encoding='utf-8') as cf:
                    import csv; writer = csv.writer(cf); writer.writerow([ts, text])
            except:
                pass

    def save_log(self):
        p = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text','*.txt')])
        if not p:
            return
        self.log_file = p
        with open(self.log_file,'w',encoding='utf-8') as f:
            f.write(f"Log started {datetime.datetime.utcnow().isoformat()}Z\n")
        messagebox.showinfo('Saved','Log will be appended to: ' + p)

    def export_csv(self):
        p = filedialog.asksaveasfilename(defaultextension='.csv', filetypes=[('CSV','*.csv')])
        if not p:
            return
        self.csv_file = p
        with open(self.csv_file,'w',newline='',encoding='utf-8') as cf:
            import csv; writer=csv.writer(cf); writer.writerow(['timestamp','message'])
        messagebox.showinfo('Saved','CSV will be appended to: ' + p)

    def start_web(self):
        if not self.monitor:
            messagebox.showerror('Error','Start monitor first')
            return
        if not FLASK_AVAILABLE:
            messagebox.showerror('Error','Flask not installed. Run: pip install flask')
            return
        try:
            self.web_thread = start_flask_dashboard(self.monitor, host='127.0.0.1', port=5000)
            self.log('Web dashboard started at http://127.0.0.1:5000')
        except Exception as e:
            messagebox.showerror('Error','Failed to start web dashboard: ' + str(e))

    def stop_web(self):
        self.web_thread = None
        self.log('Web dashboard stop requested (restart program to fully stop Flask thread).')

def main():
    root = tk.Tk(); app = App(root); root.mainloop()

if __name__ == '__main__':
    main()
