"""takuma_usb - Lightweight USB Antivirus

ตรวจจับ USB ที่เสียบเข้ามา แล้วสแกน:
  1. autorun.inf (แจ้งเตือน)
  2. ไฟล์ทั้งหมด เทียบ MD5 กับ ClamAV signature database (.hdb)

การใช้งาน:
  python takuma_usb.py                    # เฝ้ารอ USB เสียบเข้ามา
  python takuma_usb.py --scan E:\         # สแกน drive ที่ระบุทันที
  python takuma_usb.py --sig main.hdb     # ระบุ signature file เอง
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import time
from pathlib import Path

# ตรวจสอบว่าเป็น Windows หรือไม่ เพราะ WMI ใช้ได้แค่บน Windows
if sys.platform != "win32":
    sys.exit("[!] takuma_usb รองรับการทำงานบน Windows เท่านั้น (จำเป็นต้องใช้ WMI)")

try:
    import pythoncom
    import wmi
except ImportError:
    sys.exit("[!] ต้องติดตั้ง dependencies ก่อน:  pip install wmi pywin32")

DEFAULT_SIG_PATH = Path(__file__).parent / "signatures.hdb"
CHUNK_SIZE = 1 << 20          # 1 MB — syscall น้อยลง throughput สูงขึ้น
MAX_SCAN_SIZE = 100 << 20     # 100 MB — malware ส่วนใหญ่มักมีขนาดไม่เกินนี้
MMAP_THRESHOLD = 4 << 20      # ไฟล์ใหญ่กว่า 4MB ใช้ mmap

# โครงสร้าง signature: {filesize: {md5: malware_name}}
SigDB = dict[int, dict[str, str]]


def load_signatures(path: Path) -> SigDB:
    """โหลด ClamAV .hdb format: MD5:filesize:MalwareName, index ตาม size"""
    if not path.exists():
        print(f"[!] ไม่พบ signature file: {path}")
        print("    ดาวน์โหลด main.cvd จาก https://database.clamav.net/main.cvd")
        print("    แล้วใช้ sigtool --unpack main.cvd จะได้ main.hdb")
        print("    (รันต่อได้ แต่จะตรวจจับได้แค่ autorun.inf เท่านั้น)\n")
        return {}

    sigs: SigDB = {}
    total = 0
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) < 3 or len(parts[0]) != 32:
                continue
            try:
                size = int(parts[1]) if parts[1] != "*" else -1
            except ValueError:
                continue
            sigs.setdefault(size, {})[parts[0].lower()] = parts[2]
            total += 1
    print(f"[+] โหลด signatures: {total:,} รายการ ({len(sigs):,} unique sizes)")
    return sigs


def md5_file(path: Path, size: int) -> str | None:
    """hash ไฟล์ — ใช้ mmap ถ้าใหญ่พอเพื่อลด copy overhead"""
    try:
        h = hashlib.md5()
        with path.open("rb") as f:
            # ใช้ mmap หากไฟล์มีขนาดใหญ่กว่าที่กำหนดและไฟล์ไม่ว่างเปล่า
            if size >= MMAP_THRESHOLD and size > 0:
                import mmap
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    h.update(mm)
            else:
                while chunk := f.read(CHUNK_SIZE):
                    h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError, ValueError):
        return None


def scan_drive(drive: str, sigs: SigDB) -> list[tuple[Path, str]]:
    threats: list[tuple[Path, str]] = []
    root = Path(drive)

    if not root.exists():
        print(f"[!] ไม่พบ Drive: {drive} หรือไม่สามารถเข้าถึงได้")
        return threats

    autorun = root / "autorun.inf"
    if autorun.is_file():
        threats.append((autorun, "Suspicious.Autorun"))

    known_sizes = set(sigs.keys())
    has_wildcard = -1 in known_sizes

    scanned = hashed = skipped_size = skipped_big = 0
    t0 = time.perf_counter()

    for path in root.rglob("*"):
        try:
            if not path.is_file():
                continue
            fsize = path.stat().st_size
        except OSError:
            # กรณีไฟล์ถูกล็อกหรือ USB โดนดึงออกกลางคัน
            continue

        scanned += 1
        if scanned % 100 == 0:
            print(f"    สแกน {scanned} | hash {hashed} | skip size {skipped_size}", end="\r")

        if not sigs:
            continue
        if fsize > MAX_SCAN_SIZE:
            skipped_big += 1
            continue
        
        # --- size pre-filter — ตัดไฟล์ส่วนใหญ่ได้โดยไม่ต้อง hash ---
        if not has_wildcard and fsize not in known_sizes:
            skipped_size += 1
            continue

        hashed += 1
        digest = md5_file(path, fsize)
        if not digest:
            continue
        
        for bucket_size in (fsize, -1):
            bucket = sigs.get(bucket_size)
            if bucket and digest in bucket:
                threats.append((path, bucket[digest]))
                break

    elapsed = time.perf_counter() - t0
    print(
        f"    สแกน {scanned} ไฟล์ | hash {hashed} | "
        f"skip(size) {skipped_size} | skip(>100MB) {skipped_big} | "
        f"{elapsed:.1f}s" + " " * 10
    )
    return threats


def report(drive: str, threats: list[tuple[Path, str]]) -> None:
    print(f"\n=== ผลการสแกน {drive} ===")
    if not threats:
        print("  [OK] ไม่พบภัยคุกคาม ระบบปลอดภัย\n")
        return
    print(f"  [!] พบ {len(threats)} รายการที่ต้องสงสัย:")
    for path, name in threats:
        print(f"    - {name:<30} {path}")
    print()


def get_removable_drives(c: wmi.WMI) -> list[str]:
    # DriveType=2 คือ Removable Disk (USB)
    return [d.DeviceID + "\\" for d in c.Win32_LogicalDisk(DriveType=2)]


def watch_usb(sigs: SigDB) -> None:
    pythoncom.CoInitialize()
    c = wmi.WMI()

    for drive in get_removable_drives(c):
        print(f"\n[*] พบ USB ที่เชื่อมต่ออยู่แล้ว: {drive}")
        report(drive, scan_drive(drive, sigs))

    print("[*] ระบบ Takuma USB กำลังเฝ้ารอ USB... (กด Ctrl+C เพื่อออก)")
    watcher = c.Win32_VolumeChangeEvent.watch_for(EventType=2)  # EventType 2 = Device Arrival
    while True:
        try:
            event = watcher()
            drive = event.DriveName
            if not drive.endswith("\\"):
                drive += "\\"
            time.sleep(1)  # รอให้ Windows ทำการ Mount Drive ให้เสร็จ
            print(f"\n[*] แจ้งเตือน: มี USB เสียบเข้ามาที่ {drive}")
            report(drive, scan_drive(drive, sigs))
            print("[*] กลับสู่โหมดเฝ้าระวัง...")
        except KeyboardInterrupt:
            print("\n[*] ปิดการทำงานระบบ Takuma USB")
            return
        except Exception as e:
            print(f"\n[!] เกิดข้อผิดพลาดในระบบ Monitor: {e}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Takuma USB Antivirus - Lightweight USB Scanner")
    parser.add_argument("--scan", metavar="DRIVE", help="สแกน Drive ที่ระบุแล้วจบการทำงาน (เช่น E:\\)")
    parser.add_argument("--sig", type=Path, default=DEFAULT_SIG_PATH, help="ระบุ Path ไปยังไฟล์ ClamAV .hdb")
    args = parser.parse_args()

    sigs = load_signatures(args.sig)

    if args.scan:
        drive = args.scan if args.scan.endswith("\\") else args.scan + "\\"
        report(drive, scan_drive(drive, sigs))
    else:
        watch_usb(sigs)


if __name__ == "__main__":
    main()