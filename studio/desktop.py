#!/usr/bin/env python3
"""CTF Studio desktop shell.

The web UI is rendered by WebView2 through pywebview. The existing stdlib HTTP
server runs in a background thread, so no browser tab, address bar, or external
web server is involved.
"""

from __future__ import annotations

import argparse
import ctypes
import logging
import os
import secrets
import socket
import sys
import threading
import time
import urllib.request
from pathlib import Path

APP_NAME = "CTF Studio"
MUTEX_NAME = "Local\\CTFStudioDesktop"


class _RECT(ctypes.Structure):
    _fields_ = [
        ("left", ctypes.c_long),
        ("top", ctypes.c_long),
        ("right", ctypes.c_long),
        ("bottom", ctypes.c_long),
    ]


_USER32 = None


def _user32():
    """Configure Win32 prototypes once so 64-bit window handles are not truncated."""
    global _USER32
    if _USER32 is not None:
        return _USER32
    user32 = ctypes.windll.user32
    user32.IsWindowVisible.argtypes = [ctypes.c_void_p]
    user32.IsWindowVisible.restype = ctypes.c_bool
    user32.GetWindowTextW.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.c_int,
    ]
    user32.GetWindowTextW.restype = ctypes.c_int
    user32.GetWindowRect.argtypes = [ctypes.c_void_p, ctypes.POINTER(_RECT)]
    user32.GetWindowRect.restype = ctypes.c_bool
    user32.ShowWindow.argtypes = [ctypes.c_void_p, ctypes.c_int]
    user32.ShowWindow.restype = ctypes.c_bool
    user32.BringWindowToTop.argtypes = [ctypes.c_void_p]
    user32.BringWindowToTop.restype = ctypes.c_bool
    user32.SetForegroundWindow.argtypes = [ctypes.c_void_p]
    user32.SetForegroundWindow.restype = ctypes.c_bool
    user32.SwitchToThisWindow.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    user32.FlashWindow.argtypes = [ctypes.c_void_p, ctypes.c_bool]
    user32.FlashWindow.restype = ctypes.c_bool
    _USER32 = user32
    return user32


def _bundle_dir() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))


def _find_root() -> Path | None:
    env = os.environ.get("CTF_STUDIO_ROOT")
    if env and Path(env).is_dir():
        return Path(env).resolve()
    candidates: list[Path] = []
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        candidates.extend(
            [exe.parent, exe.parent.parent, exe.parent.parent.parent, Path.cwd()]
        )
    else:
        candidates.extend([Path(__file__).resolve().parent.parent, Path.cwd()])
    for candidate in candidates:
        if (candidate / "studio" / "server.py").is_file() and (
            candidate / "bin" / "ctf-studio.cmd"
        ).is_file():
            return candidate.resolve()
    return None


def _find_web(root: Path) -> Path | None:
    env = os.environ.get("CTF_STUDIO_WEB")
    if env and Path(env).is_dir():
        return Path(env).resolve()
    if getattr(sys, "frozen", False):
        bundled = _bundle_dir() / "studio" / "web"
        if bundled.is_dir():
            return bundled.resolve()
    source = root / "studio" / "web"
    if source.is_dir():
        return source.resolve()
    return None


def _free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _work_area() -> tuple[int, int, int, int]:
    if os.name != "nt":
        return (0, 0, 1280, 800)
    try:
        rect = _RECT()
        ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0)
        width = int(rect.right - rect.left)
        height = int(rect.bottom - rect.top)
        if width > 400 and height > 300:
            return (int(rect.left), int(rect.top), width, height)
    except Exception:
        pass
    return (0, 0, 1280, 800)


def _system_scale() -> float:
    """Return the system DPI scale (1.0 at 96 DPI, 1.5 at 150%)."""
    if os.name != "nt":
        return 1.0
    try:
        dpi = int(ctypes.windll.user32.GetDpiForSystem())
        if dpi > 0:
            return max(1.0, dpi / 96.0)
    except Exception:
        pass
    try:
        hdc = ctypes.windll.user32.GetDC(0)
        if hdc:
            dpi = int(ctypes.windll.gdi32.GetDeviceCaps(hdc, 88))
            ctypes.windll.user32.ReleaseDC(0, hdc)
            if dpi > 0:
                return max(1.0, dpi / 96.0)
    except Exception:
        pass
    return 1.0


def _logical_work_area() -> tuple[int, int, int, int]:
    """Window sizes in pywebview are DIPs, while Win32 reports physical pixels."""
    x, y, width, height = _work_area()
    scale = _system_scale()
    return (
        int(x / scale),
        int(y / scale),
        int(width / scale),
        int(height / scale),
    )


def _enable_dpi_awareness() -> None:
    """Make WebView2 and Win32 window geometry agree on a scaled display."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.user32.SetProcessDpiAwarenessContext(-4)  # PER_MONITOR_AWARE_V2
        return
    except Exception:
        pass
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)  # PER_MONITOR_AWARE
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def _message(text: str, *, error: bool = True) -> None:
    flags = 0x10 if error else 0x40
    try:
        ctypes.windll.user32.MessageBoxW(None, text, APP_NAME, flags)
    except Exception:
        print(text, file=sys.stderr)


def _find_existing_window() -> int:
    if os.name != "nt":
        return 0
    try:
        user32 = _user32()
        found: list[int] = []

        def callback(hwnd: int, _lparam: int) -> bool:
            if not user32.IsWindowVisible(hwnd):
                return True
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if buf.value.strip() != APP_NAME:
                return True
            rect = _RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(rect))
            if rect.right - rect.left < 300 or rect.bottom - rect.top < 200:
                return True
            found.append(int(hwnd))
            return True

        callback_type = ctypes.WINFUNCTYPE(
            ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p
        )
        user32.EnumWindows(callback_type(callback), 0)
        return found[0] if found else 0
    except Exception:
        return 0


def _focus_window(hwnd: int) -> bool:
    if not hwnd or os.name != "nt":
        return False
    try:
        user32 = _user32()
        user32.ShowWindow(hwnd, 9)  # SW_RESTORE
        user32.BringWindowToTop(hwnd)
        if not user32.SetForegroundWindow(hwnd):
            # SwitchToThisWindow is undocumented but reliably raises a window
            # that belongs to our own process when the foreground lock is held.
            user32.SwitchToThisWindow(hwnd, True)
        user32.FlashWindow(hwnd, True)
        return True
    except Exception:
        return False


def _focus_existing(timeout: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        hwnd = _find_existing_window()
        if hwnd and _focus_window(hwnd):
            return True
        time.sleep(0.15)
    return False


def _install_resize_hooks(window) -> None:
    """Force WebView2 to re-sync its bounds after maximize/restore.

    pywebview normally forwards WinForms resize events, but WebView2 can keep
    stale controller bounds on some DPI/multi-monitor setups, which looks like
    the page is zoomed and clipped at the right and bottom edges.
    """
    pending: dict[str, threading.Timer | None] = {"timer": None}

    def apply_size() -> None:
        try:
            width = int(window.width or 0)
            height = int(window.height or 0)
            if width > 200 and height > 200:
                window.resize(width, height)
        except Exception:
            pass

    def schedule(*_args) -> None:
        timer = pending.get("timer")
        if timer is not None:
            timer.cancel()
        timer = threading.Timer(0.25, apply_size)
        timer.daemon = True
        pending["timer"] = timer
        timer.start()

    for name in ("maximized", "restored", "resized"):
        event = getattr(window.events, name, None)
        if event is not None:
            try:
                event += schedule
            except Exception:
                pass


def _single_instance() -> int | None:
    if os.name != "nt":
        return 1
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    handle = kernel32.CreateMutexW(None, False, MUTEX_NAME)
    if not handle:
        return 1
    if kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
        # Focus the existing window instead of showing a message box.  The old
        # FindWindow-based lookup silently failed on some DPI/multi-monitor
        # setups and produced one "already running" popup per double-click.
        _focus_existing()
        return None
    return int(handle)


def main() -> int:
    parser = argparse.ArgumentParser(description="CTF Studio desktop shell")
    parser.add_argument("--smoke", action="store_true", help="close after a few seconds")
    parser.add_argument("--smoke-seconds", type=float, default=4.0)
    parser.add_argument(
        "--check",
        action="store_true",
        help="start the local service, verify it, and exit without opening a window",
    )
    args = parser.parse_args()
    _enable_dpi_awareness()

    root = _find_root()
    if root is None:
        _message(
            "找不到 muteki-ctf-integration 目录。\n\n"
            "请把 CTFStudio.exe 放在仓库根目录或 bin/ 下，"
            "或设置环境变量 CTF_STUDIO_ROOT 指向仓库根。"
        )
        return 2
    web = _find_web(root)
    if web is None:
        _message("找不到 studio/web 界面文件；安装目录不完整。")
        return 2

    os.environ["CTF_STUDIO_ROOT"] = str(root)
    os.environ["CTF_STUDIO_HOME"] = str(root / "studio")
    os.environ["CTF_STUDIO_WEB"] = str(web)
    os.environ["CTF_STUDIO_RUNS"] = str(root / "studio" / "runs")
    os.environ["CTF_STUDIO_EXPERIENCE"] = str(root / "studio" / "experience.jsonl")
    os.environ.setdefault("CTF_STUDIO_TOKEN", secrets.token_urlsafe(24))
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")

    log_path = root / "studio" / "desktop.log"
    logging.basicConfig(
        filename=str(log_path),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )

    if not args.check:
        mutex = _single_instance()
        if mutex is None:
            logging.info("second launch focused the existing window")
            return 0

    # The server module reads the environment above at import time, so import it
    # only after the real tool root and the bundled web directory are known.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import server  # type: ignore

    runs_dir = Path(os.environ["CTF_STUDIO_RUNS"])
    runs_dir.mkdir(parents=True, exist_ok=True)
    port = _free_port()
    try:
        httpd = server.build_server(
            "127.0.0.1", port, runs_dir, os.environ["CTF_STUDIO_TOKEN"]
        )
    except Exception as exc:
        logging.exception("server start failed")
        _message(f"CTF Studio 服务启动失败：{type(exc).__name__}: {exc}")
        return 1

    threading.Thread(
        target=httpd.serve_forever,
        name="ctf-studio-http",
        daemon=True,
    ).start()
    url = f"http://127.0.0.1:{port}/"
    for _ in range(120):
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                if response.status == 200:
                    break
        except Exception:
            time.sleep(0.1)
    else:
        httpd.shutdown()
        httpd.server_close()
        _message("CTF Studio 本地服务没有在预期时间内就绪。")
        return 1

    if args.check:
        token = os.environ["CTF_STUDIO_TOKEN"]
        api_url = f"{url}api/status?token={token}"
        try:
            with urllib.request.urlopen(api_url, timeout=20) as response:
                status = response.read().decode("utf-8", "replace")
            print(
                f"OK {url} status={status[:160]} scale={_system_scale():.2f} "
                f"logical={_logical_work_area()}"
            )
            return 0
        except Exception as exc:
            print(f"CHECK FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1
        finally:
            httpd.shutdown()
            httpd.server_close()

    try:
        import webview  # type: ignore
    except Exception as exc:
        httpd.shutdown()
        httpd.server_close()
        _message(f"WebView2 组件不可用：{type(exc).__name__}: {exc}")
        return 1

    work_x, work_y, work_w, work_h = _logical_work_area()
    width = min(1180, work_w, max(920, work_w - 64))
    height = min(820, work_h, max(620, work_h - 64))
    x = max(work_x, work_x + (work_w - width) // 2)
    y = max(work_y, work_y + (work_h - height) // 2)
    logging.info(
        "window geometry: %sx%s at %s,%s (logical work %sx%s, raw work %s, scale %.2f)",
        width,
        height,
        x,
        y,
        work_w,
        work_h,
        _work_area(),
        _system_scale(),
    )
    window = webview.create_window(
        APP_NAME,
        url,
        width=width,
        height=height,
        x=x,
        y=y,
        min_size=(900, 600),
        background_color="#f4f2fa",
        text_select=True,
    )
    _install_resize_hooks(window)
    if args.smoke:
        threading.Timer(max(1.0, args.smoke_seconds), window.destroy).start()

    def _initial_sync() -> None:
        # Setting the size once after the GUI loop starts forces WebView2 to
        # adopt the real window bounds instead of its pre-show size.
        deadline = time.monotonic() + 12.0
        while time.monotonic() < deadline:
            try:
                if window.evaluate_js("document.readyState") in ("interactive", "complete"):
                    break
            except Exception:
                pass
            time.sleep(0.2)
        try:
            window.resize(width, height)
            window.move(x, y)
        except Exception:
            pass

        # WinForms applies the monitor scale to the form, and some WebView2
        # versions apply it a second time to the page.  The result is a
        # devicePixelRatio above the real monitor scale: the UI looks zoomed
        # and the right/bottom edges are clipped.  Measure it and compensate.
        try:
            dpr = float(window.evaluate_js("window.devicePixelRatio") or 1.0)
            screen_css = float(window.evaluate_js("screen.width") or 0.0)
            work_width = float(_work_area()[2] or 0.0)
            if dpr > 0 and screen_css > 0 and work_width > 0:
                expected = (screen_css * dpr) / work_width
                native = getattr(window, "native", None)
                view = getattr(native, "webview", None)
                if view is not None and dpr > expected * 1.05:
                    factor = max(0.5, min(1.0, expected / dpr))
                    view.ZoomFactor = factor
                    logging.info(
                        "webview zoom corrected: dpr=%.2f expected=%.2f factor=%.3f",
                        dpr,
                        expected,
                        factor,
                    )
                    logging.info(
                        "webview after correction: dpr=%.2f inner=%sx%s",
                        float(window.evaluate_js("window.devicePixelRatio") or 0),
                        window.evaluate_js("window.innerWidth"),
                        window.evaluate_js("window.innerHeight"),
                    )
        except Exception:
            logging.exception("webview zoom correction failed")

    logging.info("desktop window opened: %s", url)
    try:
        try:
            webview.start(
                func=_initial_sync,
                gui="edgechromium",
                private_mode=False,
                storage_path=str(root / "studio" / ".desktop-profile"),
            )
        except TypeError:
            webview.start(func=_initial_sync, gui="edgechromium", private_mode=False)
    finally:
        httpd.shutdown()
        httpd.server_close()
        logging.info("desktop window closed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
