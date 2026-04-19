# Takuma USB Antivirus 🛡️

**Takuma USB** is a blazingly fast, lightweight, open-source **antivirus for USB** flash drives written in Python. It automatically detects when a USB drive is inserted into your Windows machine and immediately scans it for malware, trojans, and malicious `autorun.inf` files.

If you are looking for a reliable **USB malware scanner** that doesn't consume heavy system resources, Takuma USB is designed for you. It utilizes ClamAV's signature database to accurately identify known threats.

## 🚀 Features
- **Real-Time USB Monitoring:** Automatically detects and scans newly inserted USB flash drives using Windows WMI.
- **Autorun Malware Detection:** Instantly flags suspicious `autorun.inf` files commonly used by worms to spread via removable media.
- **High-Performance Scanning:** - Uses **Size Pre-filtering** to skip safe files without wasting CPU cycles on hashing.
  - Implements **Memory-Mapped Files (mmap)** for lightning-fast scanning of large payloads.
- **ClamAV Signature Support:** Compatible with standard ClamAV `.hdb` (MD5 Hash) databases.
- **Portable & Lightweight:** No heavy background services. Run it directly via command line.

## ⚙️ Prerequisites

This tool requires Windows (due to WMI dependency) and Python 3.8+:

    pip install -r requirements.txt

---

## 📥 Getting Signature Updates (การอัปเดตฐานข้อมูลไวรัส)

To make this the best antivirus for USB, you need an up-to-date virus signature database.

- Download the latest `main.cvd` from ClamAV Database  
- Use `sigtool` (included in ClamAV) to unpack it:

    sigtool --unpack main.cvd

- Place the generated `main.hdb` file in the same directory as the script  
  หรือ rename เป็น `signatures.hdb`

---

## 💻 Usage (วิธีใช้งาน)

### 1. Real-Time Monitor Mode / โหมดเฝ้าระวัง (Default)
Run the script to start watching for any USB insertions.  
รันสคริปต์ทิ้งไว้ โปรแกรมจะเฝ้ารอ เมื่อมี USB เสียบเข้ามาจะสแกนอัตโนมัติ:

    python takuma_usb.py

---

### 2. Manual Scan Mode / โหมดสแกนแบบระบุไดรฟ์
Scan a specific drive letter and exit.  
สแกน drive ที่ระบุทันทีแล้วจบการทำงาน (ตัวอย่าง: สแกนไดรฟ์ E:):

    python takuma_usb.py --scan E:\

---

### 3. Custom Signature File / โหมดระบุไฟล์ Database
Specify a custom ClamAV `.hdb` file.  
ระบุที่อยู่ไฟล์ Database (.hdb) เอง:

    python takuma_usb.py --sig custom_database.hdb

---

## 🛡️ Security Disclaimer

Takuma USB is a diagnostic tool designed to help identify malicious files on removable media.  
It should be used as an additional layer of security alongside your primary Endpoint Detection and Response (EDR) or main antivirus solution.
