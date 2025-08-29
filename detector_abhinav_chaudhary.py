#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import csv
import json
import re
from typing import Tuple, Dict, Any

RE_10_DIGIT_PHONE = re.compile(r'(?<!\d)(?:\+?91[-\s]?)?([6-9]\d{9})(?!\d)')
RE_12_DIGIT_AADHAR = re.compile(r'(?<!\d)(\d{4})[ -]?(\d{4})[ -]?(\d{4})(?!\d)')
RE_PASSPORT = re.compile(r'\b([A-PR-WYa-pr-wy][0-9]{7})\b')
RE_UPI = re.compile(r'\b([A-Za-z0-9.\-_]{2,})@([a-z]{2,})\b')
RE_EMAIL = re.compile(r'([A-Za-z0-9._%+\-]+)@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})')
RE_IP = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3})\b')
RE_PIN = re.compile(r'(?<!\d)(\d{6})(?!\d)')

def mask_keep_edges(s: str, keep_start: int, keep_end: int, fill_char: str = "X") -> str:
    if len(s) <= keep_start + keep_end:
        return fill_char * len(s)
    return s[:keep_start] + (fill_char * (len(s) - keep_start - keep_end)) + s[-keep_end:]

def mask_name(full_name: str) -> str:
    parts = [p for p in re.split(r'\s+', full_name.strip()) if p]
    masked = []
    for p in parts:
        first = p[0]
        masked.append(first + "XXX")
    return " ".join(masked)

def redact_value(val: Any) -> Tuple[Any, bool]:
    found = False
    if not isinstance(val, str):
        return (val, False)

    original = val


    def repl_phone(m):
        nonlocal found
        found = True
        num = m.group(1)
        return mask_keep_edges(num, 2, 2)
    val = RE_10_DIGIT_PHONE.sub(repl_phone, val)


    def repl_aadhar(m):
        nonlocal found
        found = True
        g1,g2,g3 = m.group(1), m.group(2), m.group(3)
        return f"{g1} XXXX XXXX"
    val = RE_12_DIGIT_AADHAR.sub(repl_aadhar, val)

 
    def repl_passport(m):
        nonlocal found
        found = True
        p = m.group(1)
        return p[0] + "XXXXXXX"
    val = RE_PASSPORT.sub(repl_passport, val)


    def repl_upi(m):
        nonlocal found
        found = True
        user, dom = m.group(1), m.group(2)
        user_masked = (user[:2] + "XXX") if len(user) > 2 else "XXX"
        return f"{user_masked}@{dom}"
    val = RE_UPI.sub(repl_upi, val)


    return (val, found)

def redact_email(val: str) -> str:
    def repl(m):
        user, dom = m.group(1), m.group(2)
        user_masked = (user[:2] + "XXX") if len(user) > 2 else "XXX"
        return f"{user_masked}@{dom}"
    return RE_EMAIL.sub(repl, val)

def is_full_name(name: str) -> bool:
    parts = [p for p in re.split(r'\s+', name.strip()) if p]
    return len(parts) >= 2

def address_like(obj: Dict[str, Any]) -> bool:
    addr = str(obj.get("address", "")).strip()
    city = str(obj.get("city", "")).strip()
    state = str(obj.get("state", "")).strip()
    pin = str(obj.get("pin_code", "")).strip()
    if addr and (RE_PIN.search(pin) or city or state):
        return True
    return False

def device_or_ip_tied(obj: Dict[str, Any]) -> bool:
    has_device_or_ip = bool(obj.get("device_id") or obj.get("ip_address"))
    tied = bool(obj.get("email") or obj.get("name") or obj.get("customer_id") or obj.get("username"))
    return has_device_or_ip and tied

def detect_combinatorial(obj: Dict[str, Any]) -> Tuple[int, Dict[str, bool]]:
    flags = {
        "name": False,
        "email": False,
        "address": False,
        "device_ip": False,
    }

    name_val = str(obj.get("name", "")).strip()
    if name_val and is_full_name(name_val):
        flags["name"] = True

    email_val = str(obj.get("email", "")).strip()
    if email_val and RE_EMAIL.search(email_val):
        flags["email"] = True

    if address_like(obj):
        flags["address"] = True
 
    if device_or_ip_tied(obj):
        flags["device_ip"] = True

    count = sum(flags.values())
    return count, flags

def redact_record(obj: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    obj = dict(obj) 
    pii_found = False

    for k, v in list(obj.items()):
        red_v, found = redact_value(v)
        if found:
            pii_found = True
        obj[k] = red_v

   
    if "phone" in obj and isinstance(obj["phone"], str):
        m = RE_10_DIGIT_PHONE.search(obj["phone"])
        if m:
            obj["phone"] = mask_keep_edges(m.group(1), 2, 2)
            pii_found = True

    if "aadhar" in obj and isinstance(obj["aadhar"], str):
        m = RE_12_DIGIT_AADHAR.search(obj["aadhar"])
        if m:
            obj["aadhar"] = f"{m.group(1)} XXXX XXXX"
            pii_found = True

    if "passport" in obj and isinstance(obj["passport"], str):
        m = RE_PASSPORT.search(obj["passport"])
        if m:
            p = m.group(1)
            obj["passport"] = p[0] + "XXXXXXX"
            pii_found = True

    if "upi_id" in obj and isinstance(obj["upi_id"], str):
        m = RE_UPI.search(obj["upi_id"])
        if m:
            user, dom = m.group(1), m.group(2)
            user_masked = (user[:2] + "XXX") if len(user) > 2 else "XXX"
            obj["upi_id"] = f"{user_masked}@{dom}"
            pii_found = True


    count, flags = detect_combinatorial(obj)
    is_combinatorial_pii = count >= 2
    if is_combinatorial_pii:
    
        if flags["name"] and isinstance(obj.get("name"), str):
            obj["name"] = mask_name(obj["name"])
        if flags["email"] and isinstance(obj.get("email"), str):
            obj["email"] = redact_email(obj["email"])
        if flags["address"] and isinstance(obj.get("address"), str):
            obj["address"] = "[REDACTED_ADDRESS]"
        if flags["device_ip"]:
            if isinstance(obj.get("ip_address"), str) and obj["ip_address"]:
                obj["ip_address"] = "***.***.***.***"
            if isinstance(obj.get("device_id"), str) and obj["device_id"]:
                obj["device_id"] = "[REDACTED_DEVICE]"
        pii_found = True or pii_found  # ensure true

   
    return obj, (pii_found or is_combinatorial_pii)

def process(input_csv: str, output_csv: str) -> None:
    with open(input_csv, newline='', encoding='utf-8') as f_in, open(output_csv, 'w', newline='', encoding='utf-8') as f_out:
        reader = csv.DictReader(f_in)
        writer = csv.DictWriter(f_out, fieldnames=["record_id", "redacted_data_json", "is_pii"])
        writer.writeheader()
        for row in reader:
            record_id = row.get("record_id")
            data_json = row.get("Data_json", row.get("data_json", ""))

            try:
                data_obj = json.loads(data_json)
            except Exception:
                data_obj = {"raw": data_json}

            redacted_obj, is_pii_flag = redact_record(data_obj)

            writer.writerow({
                "record_id": record_id,
                "redacted_data_json": json.dumps(redacted_obj, ensure_ascii=False),
                "is_pii": str(bool(is_pii_flag))
            })

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 detector_abhinav_chaudhary.py input.csv")
        sys.exit(1)
    process(sys.argv[1], "redacted_output_abhinav_chaudhary.csv")
