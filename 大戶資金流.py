# ==============================================================================
# 大戶資金流.py
# 🛰️ [馬會 9 大彩池全量黑盒飛行記錄儀 - 海外/本地獨立專用版]
# 
# 功能說明：
# 1. 完全獨立運行，無任何本地 AI/歷史戰績/排位表依賴，絕不因海外賽事卡死。
# 2. 自動監控並秒級錄影 9 大彩池：WIN, PLA, QIN, QPL, TCE, TRI, FF, QTT, FCT, DBL。
# 3. 實時動態解析海外/本地賽事各駒本金 (獨贏、位置、連贏Q涉資、位置QP涉資、單T、三重彩、孖上/孖下)。
# 4. 逐秒追加寫入高精度黑盒記錄檔 (./Race_Recordings/REC_{date}_{venue}_R{race}.jsonl)。
# 5. 斷電不丟失 (行緩衝 Line-buffered)，為後續 007 逆向推導提供 100% 完整無損數據。
# ==============================================================================

import asyncio
from collections import deque
from datetime import datetime
import json
import os
import sys
import time
import zlib
from playwright.async_api import async_playwright

# 終端機顏色輸出
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    BG_BLUE = '\033[44m'
    BG_RED = '\033[41m'
    BG_GREEN = '\033[42m'

# 監聽之核心彩池與頁面代號
POOL_PAGE_CONFIG = [
    {"pool_id": "wpq", "name": "獨贏/位置/連贏/位置Q"},
    {"pool_id": "tce", "name": "三重彩 (TCE)"},
    {"pool_id": "tri", "name": "單T (TRI)"},
    {"pool_id": "ff",  "name": "四連環 (F-F)"},
    {"pool_id": "qtt", "name": "四重彩 (QTT)"},
    {"pool_id": "fct", "name": "二重彩 (FCT)"},
    {"pool_id": "dbl", "name": "孖寶 (DBL)"},
]

ALL_KNOWN_POOLS = ["win", "pla", "qin", "qpl", "tce", "tri", "ff", "qtt", "fct", "dbl"]

# ========================== 核心數據狀態儲存器 ==========================
POOL_TOTALS = {p: 0.0 for p in ALL_KNOWN_POOLS}
POOL_PACKET_COUNTS = {p: 0 for p in ALL_KNOWN_POOLS}
SNIFFER_LOGS = deque(maxlen=8)

# 各駒獨立資金池 (動態支援 1 ~ 24 號馬)
HORSE_WIN_ODDS = {}
HORSE_WIN_STAKES = {}
HORSE_PLA_ODDS = {}
HORSE_PLA_STAKES = {}
HORSE_QIN_EXPOSURE = {}
HORSE_QPL_EXPOSURE = {}
HORSE_TRI_STAKES = {}
HORSE_TCE_STAKES = {}
HORSE_DBL_UP_STAKES = {}
HORSE_DBL_DOWN_STAKES = {}

COMBOS_MATRIX = {"qin": {}, "qpl": {}}
ACTIVE_RUNNERS = set()
FRAME_COUNTER = 0
RECORD_START_TIME = 0.0

# ========================== 黑盒飛行記錄儀 ==========================
class RaceFlightRecorder:
    def __init__(self, race_date, venue, race_no):
        self.dir_path = os.path.abspath("./Race_Recordings")
        os.makedirs(self.dir_path, exist_ok=True)
        clean_v = venue.replace(" ", "").upper()
        clean_d = race_date.replace("-", "").replace("/", "")
        self.filename = os.path.join(self.dir_path, f"REC_{clean_d}_{clean_v}_R{race_no}.jsonl")
        # 行緩衝模式 (buffering=1)，即寫即存，絕不因當機丟失
        self.file = open(self.filename, "a", encoding="utf-8", buffering=1)
        print(f"\n{Colors.BG_GREEN}{Colors.WHITE}{Colors.BOLD} 📼 【黑盒飛行記錄儀啟動】存檔路徑: {self.filename} {Colors.RESET}")

    def write_frame(self, frame_data):
        try:
            if self.file and not self.file.closed:
                line = json.dumps(frame_data, ensure_ascii=False) + "\n"
                self.file.write(line)
                return True
        except Exception as e:
            pass
        return False

    def close(self):
        try:
            if self.file and not self.file.closed:
                self.file.flush()
                self.file.close()
        except Exception:
            pass

GLOBAL_RECORDER = None

# ========================== 核心 MQTT 與 GZIP 解碼 ==========================
def find_and_decompress_gzip(data):
    GZIP_MAGIC = b"\x1f\x8b"
    start_offset = 0
    while True:
        idx = data.find(GZIP_MAGIC, start_offset)
        if idx == -1:
            break
        try:
            return zlib.decompress(data[idx:], 31).decode("utf-8")
        except:
            start_offset = idx + 1
    return None

def parse_mqtt_stream(buffer):
    packets = []
    offset = 0
    buf_len = len(buffer)
    while offset < buf_len:
        if offset + 2 > buf_len:
            break
        header_byte = buffer[offset]
        packet_type = header_byte & 0xF0
        len_offset = offset + 1
        multiplier = 1
        rem_length = 0
        try:
            while True:
                if len_offset >= buf_len:
                    raise ValueError
                digit = buffer[len_offset]
                rem_length += (digit & 127) * multiplier
                multiplier *= 128
                len_offset += 1
                if (digit & 128) == 0:
                    break
        except:
            break
        header_len = len_offset - offset
        total_packet_len = header_len + rem_length
        if offset + total_packet_len > buf_len:
            break
        packets.append((packet_type, buffer[offset: offset + total_packet_len]))
        offset += total_packet_len
    return packets

def process_packet(packet_type, payload):
    if packet_type == 0x30:
        try:
            offset = 1
            while offset < len(payload):
                if (payload[offset] & 128) == 0:
                    offset += 1
                    break
                offset += 1
            if offset + 2 > len(payload):
                return None, None
            topic_len = (payload[offset] << 8) | payload[offset + 1]
            offset += 2
            try:
                topic = payload[offset: offset + topic_len].decode("utf-8")
            except:
                topic = "unknown"
            content = payload[offset + topic_len:]
            text = find_and_decompress_gzip(content)
            if not text:
                try:
                    t = content.decode("utf-8", errors="ignore")
                    if "{" in t and "}" in t:
                        s = t.find("{")
                        e = t.rfind("}") + 1
                        text = t[s:e]
                except:
                    pass
            return topic, text
        except:
            pass
    return None, None

# ========================== 封包分流與實時數據解算 ==========================
def dispatch_raw_packet(topic, payload_json, target_race, prev_race):
    global POOL_TOTALS, POOL_PACKET_COUNTS, SNIFFER_LOGS, ACTIVE_RUNNERS
    global HORSE_WIN_ODDS, HORSE_WIN_STAKES, HORSE_PLA_ODDS, HORSE_PLA_STAKES
    global HORSE_QIN_EXPOSURE, HORSE_QPL_EXPOSURE, HORSE_TRI_STAKES, HORSE_TCE_STAKES
    global HORSE_DBL_UP_STAKES, HORSE_DBL_DOWN_STAKES, COMBOS_MATRIX

    t_lower = topic.lower()
    now_str = datetime.now().strftime("%H:%M:%S")

    # 1. 識別彩池代號
    detected_pool = "other"
    for p in ["win", "pla", "wp", "qin", "qpl", "tce", "tri", "ff", "f-f", "qtt", "fct", "dbl"]:
        if f"/{p}/" in t_lower:
            detected_pool = p.replace("-", "")
            break

    POOL_PACKET_COUNTS[detected_pool] = POOL_PACKET_COUNTS.get(detected_pool, 0) + 1

    # 2. 抓取彩池總投注額 (全兼容 pInv, inv, ttlInv.net, mgPl.ttlInv.net)
    pool_inv = 0.0
    if "pInv" in payload_json:
        pool_inv = float(payload_json["pInv"] or 0.0)
    elif "inv" in payload_json and not isinstance(payload_json["inv"], list):
        pool_inv = float(payload_json["inv"] or 0.0)
    elif "ttlInv" in payload_json and isinstance(payload_json["ttlInv"], dict):
        pool_inv = float(payload_json["ttlInv"].get("net", 0.0) or 0.0)
    elif "mgPl" in payload_json and isinstance(payload_json["mgPl"], dict):
        sub = payload_json["mgPl"].get("ttlInv", {})
        if isinstance(sub, dict):
            pool_inv = float(sub.get("net", 0.0) or 0.0)

    # 判斷是否為上一場孖寶 (用於解算孖上)
    is_prev_dbl = (detected_pool == "dbl" and prev_race > 0 and (f"/{prev_race:02d}/" in t_lower or f"/{prev_race}/" in t_lower))

    if pool_inv > 0 and not is_prev_dbl:
        POOL_TOTALS[detected_pool] = pool_inv

    # 3. 提取組合或各駒數據
    cmb_list = payload_json.get("cbs") or payload_json.get("cmb") or []
    item_count = len(cmb_list)

    # (A) 獨贏 WIN 解析
    if detected_pool == "win" and cmb_list:
        for item in cmb_list:
            try:
                cb_str = str(item.get("cb", "")).strip()
                if cb_str.isdigit():
                    h_no = int(cb_str)
                    ACTIVE_RUNNERS.add(h_no)
                    HORSE_WIN_ODDS[h_no] = float(item.get("ods", item.get("wP", 0.0)) or 0.0)
                    HORSE_WIN_STAKES[h_no] = float(item.get("inv", 0.0) or 0.0)
            except:
                continue

    # (B) 位置 PLA 解析
    elif detected_pool == "pla" and cmb_list:
        for item in cmb_list:
            try:
                cb_str = str(item.get("cb", "")).strip()
                if cb_str.isdigit():
                    h_no = int(cb_str)
                    ACTIVE_RUNNERS.add(h_no)
                    HORSE_PLA_ODDS[h_no] = float(item.get("ods", item.get("wP", 0.0)) or 0.0)
                    HORSE_PLA_STAKES[h_no] = float(item.get("inv", 0.0) or 0.0)
            except:
                continue

    # (C) 連贏 QIN 解析 (計算全場組合本金與單馬穿透涉資)
    elif detected_pool == "qin" and cmb_list:
        new_q_exp = {h: 0.0 for h in ACTIVE_RUNNERS}
        for item in cmb_list:
            try:
                cb_str = str(item.get("cb", "")).strip()
                stake = float(item.get("inv", 0.0) or 0.0)
                COMBOS_MATRIX["qin"][cb_str] = stake
                parts = [int(p) for p in cb_str.replace("/", "+").split("+") if p.isdigit()]
                for p in parts:
                    ACTIVE_RUNNERS.add(p)
                    new_q_exp[p] = new_q_exp.get(p, 0.0) + stake
            except:
                continue
        HORSE_QIN_EXPOSURE.update(new_q_exp)

    # (D) 位置Q QPL 解析
    elif detected_pool == "qpl" and cmb_list:
        new_qp_exp = {h: 0.0 for h in ACTIVE_RUNNERS}
        for item in cmb_list:
            try:
                cb_str = str(item.get("cb", "")).strip()
                stake = float(item.get("inv", 0.0) or 0.0)
                COMBOS_MATRIX["qpl"][cb_str] = stake
                parts = [int(p) for p in cb_str.replace("/", "+").split("+") if p.isdigit()]
                for p in parts:
                    ACTIVE_RUNNERS.add(p)
                    new_qp_exp[p] = new_qp_exp.get(p, 0.0) + stake
            except:
                continue
        HORSE_QPL_EXPOSURE.update(new_qp_exp)

    # (E) 單T TRI 解析 (官方 invByRu 直讀單駒涉資)
    elif detected_pool == "tri":
        inv_list = payload_json.get("invByRu", {}).get("inv", [])
        if inv_list:
            item_count = len(inv_list)
            for item in inv_list:
                try:
                    r_no = int(item.get("ruNo", 0))
                    amt = float(item.get("inv", 0.0) or 0.0)
                    if r_no > 0:
                        ACTIVE_RUNNERS.add(r_no)
                        HORSE_TRI_STAKES[r_no] = amt
                except:
                    continue

    # (F) 三重彩 TCE 解析 (官方 invByRuByPos 直讀單駒涉資)
    elif detected_pool == "tce":
        inv_list = payload_json.get("invByRuByPos", {}).get("inv", [])
        if inv_list:
            item_count = len(inv_list)
            temp_tce = {}
            for item in inv_list:
                try:
                    r_no = int(item.get("ruNo", 0))
                    amt = float(item.get("inv", 0.0) or 0.0)
                    if r_no > 0:
                        ACTIVE_RUNNERS.add(r_no)
                        temp_tce[r_no] = temp_tce.get(r_no, 0.0) + amt
                except:
                    continue
            HORSE_TCE_STAKES.update(temp_tce)

    # (G) 孖寶 DBL 解析 (孖上 = 上一場次尾關; 孖下 = 當前場次頭關)
    elif detected_pool == "dbl" and cmb_list:
        if is_prev_dbl:
            # 這是上一場的 DBL 封包，提取 Leg 2 (當前場次馬號) -> 孖上
            for item in cmb_list:
                try:
                    cb_str = str(item.get("cb", item.get("cmbStr", ""))).strip()
                    stake = float(item.get("inv", 0.0) or 0.0)
                    delimiter = "/" if "/" in cb_str else ("+" if "+" in cb_str else None)
                    if delimiter and stake > 0:
                        parts = cb_str.split(delimiter)
                        leg2_horse = int(parts[1].lstrip("0"))
                        ACTIVE_RUNNERS.add(leg2_horse)
                        HORSE_DBL_UP_STAKES[leg2_horse] = HORSE_DBL_UP_STAKES.get(leg2_horse, 0.0) + stake
                except:
                    continue
        else:
            # 這是當前場次的 DBL 封包，提取 Leg 1 (當前場次馬號) -> 孖下
            for item in cmb_list:
                try:
                    cb_str = str(item.get("cb", item.get("cmbStr", ""))).strip()
                    stake = float(item.get("inv", 0.0) or 0.0)
                    delimiter = "/" if "/" in cb_str else ("+" if "+" in cb_str else None)
                    if delimiter and stake > 0:
                        parts = cb_str.split(delimiter)
                        leg1_horse = int(parts[0].lstrip("0"))
                        ACTIVE_RUNNERS.add(leg1_horse)
                        HORSE_DBL_DOWN_STAKES[leg1_horse] = HORSE_DBL_DOWN_STAKES.get(leg1_horse, 0.0) + stake
                except:
                    continue

    log_entry = (
        f"[{now_str}] 📦 收到 {detected_pool.upper():<4} 封包 | 項目: {item_count:>3} | "
        f"彩池: ${POOL_TOTALS.get(detected_pool, 0):,.0f}"
    )
    SNIFFER_LOGS.append(log_entry)

# ========================== 實時終端儀表板與逐秒寫盤 ==========================
async def render_and_record_loop(race_date, venue, target_race):
    global FRAME_COUNTER, RECORD_START_TIME, GLOBAL_RECORDER
    RECORD_START_TIME = time.time()

    while True:
        await asyncio.sleep(1.0)
        now_dt = datetime.now()
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
        elapsed_sec = int(time.time() - RECORD_START_TIME)
        elapsed_str = f"{elapsed_sec // 60:02d}:{elapsed_sec % 60:02d}"

        # 1. 匯總各彩池總額
        total_turnover = sum(POOL_TOTALS.get(p, 0.0) for p in ALL_KNOWN_POOLS)

        # 2. 構建單駒明細數據
        sorted_runners = sorted(list(ACTIVE_RUNNERS))
        total_win = POOL_TOTALS.get("win", 0.0)

        horses_record = []
        for h in sorted_runners:
            w_stake = HORSE_WIN_STAKES.get(h, 0.0)
            p_stake = HORSE_PLA_STAKES.get(h, 0.0)
            q_stake = HORSE_QIN_EXPOSURE.get(h, 0.0)
            qp_stake = HORSE_QPL_EXPOSURE.get(h, 0.0)
            tri_stake = HORSE_TRI_STAKES.get(h, 0.0)
            tce_stake = HORSE_TCE_STAKES.get(h, 0.0)
            dbl_up = HORSE_DBL_UP_STAKES.get(h, 0.0)
            dbl_down = HORSE_DBL_DOWN_STAKES.get(h, 0.0)
            odds = HORSE_WIN_ODDS.get(h, 0.0)
            pla_odds = HORSE_PLA_ODDS.get(h, 0.0)

            total_h_stake = w_stake + p_stake + q_stake + qp_stake + tri_stake + tce_stake + dbl_up + dbl_down
            win_pct = round((w_stake / total_win * 100.0), 2) if total_win > 0 else 0.0

            horses_record.append({
                "horse_no": h,
                "win_odds": odds,
                "win_stake": round(w_stake, 1),
                "pla_odds": pla_odds,
                "pla_stake": round(p_stake, 1),
                "qin_exposure": round(q_stake, 1),
                "qpl_exposure": round(qp_stake, 1),
                "tri_stake": round(tri_stake, 1),
                "tce_stake": round(tce_stake, 1),
                "dbl_up_stake": round(dbl_up, 1),
                "dbl_down_stake": round(dbl_down, 1),
                "total_stake": round(total_h_stake, 1),
                "win_pool_pct": win_pct
            })

        # 3. 組合高精度幀數據並寫入黑盒
        frame_payload = {
            "status": "RECORDING",
            "last_update": now_str,
            "record_epoch": time.time(),
            "venue": venue,
            "race_date": race_date,
            "race_no": target_race,
            "race_info": {
                "total_win_pool": POOL_TOTALS.get("win", 0.0),
                "total_pla_pool": POOL_TOTALS.get("pla", 0.0),
                "total_qin_pool": POOL_TOTALS.get("qin", 0.0),
                "total_qpl_pool": POOL_TOTALS.get("qpl", 0.0),
                "total_tce_pool": POOL_TOTALS.get("tce", 0.0),
                "total_tri_pool": POOL_TOTALS.get("tri", 0.0),
                "total_ff_pool":  POOL_TOTALS.get("ff", 0.0),
                "total_qtt_pool": POOL_TOTALS.get("qtt", 0.0),
                "total_fct_pool": POOL_TOTALS.get("fct", 0.0),
                "total_dbl_pool": POOL_TOTALS.get("dbl", 0.0),
                "total_turnover": total_turnover,
                "packet_counts": dict(POOL_PACKET_COUNTS)
            },
            "horses": horses_record,
            "combos_matrix": {
                "qin": COMBOS_MATRIX["qin"],
                "qpl": COMBOS_MATRIX["qpl"]
            }
        }

        if GLOBAL_RECORDER:
            GLOBAL_RECORDER.write_frame(frame_payload)
            FRAME_COUNTER += 1

        # 4. 刷新終端儀表板
        os.system("cls" if os.name == "nt" else "clear")
        rec_file_display = GLOBAL_RECORDER.filename if GLOBAL_RECORDER else "未指定"

        print(f"{Colors.BG_RED}{Colors.WHITE}{Colors.BOLD} 🔴 【海外/本地 9 大彩池全量黑盒飛行記錄中】 {Colors.RESET} "
              f"場次: {Colors.YELLOW}{venue} 第 {target_race} 場{Colors.RESET} | "
              f"錄影時間: {Colors.CYAN}{elapsed_str}{Colors.RESET} | "
              f"已錄幀數: {Colors.GREEN}{FRAME_COUNTER}{Colors.RESET}")
        print(f"📁 存檔文件: {Colors.WHITE}{rec_file_display}{Colors.RESET}")
        print("=" * 110)

        # 彩池總覽 (2 行排版)
        p_strs = []
        for p in ALL_KNOWN_POOLS:
            tot = POOL_TOTALS.get(p, 0.0)
            cnt = POOL_PACKET_COUNTS.get(p, 0)
            t_s = f"${tot/1000000:.2f}M" if tot >= 1000000 else (f"${tot/1000:.0f}K" if tot >= 1000 else f"${tot:.0f}")
            p_strs.append(f"{p.upper():<4}: {t_s:>8} ({cnt:>2}封)")
        
        tot_all_s = f"${total_turnover/1000000:.2f}M" if total_turnover >= 1000000 else f"${total_turnover/1000:.0f}K"
        print(f"💰 【9 大彩池實時投注總額 (全場總計: {Colors.BOLD}{Colors.YELLOW}{tot_all_s}{Colors.RESET})】:")
        print("  " + " | ".join(p_strs[:5]))
        print("  " + " | ".join(p_strs[5:]))
        print("-" * 110)

        # 各駒資金明細表
        print("🐎 【實時單駒資金流分佈榜 (實質本金)】:")
        header = f" {'馬號':<4} | {'獨贏賠率':<8} | {'獨贏本金':<10} | {'位置本金':<10} | {'連贏Q涉資':<10} | {'位置QP涉資':<10} | {'單T本金':<9} | {'三重彩本金':<10} | {'孖寶(上/下)':<12} | {'總涉資本金':<11}"
        print(f"{Colors.CYAN}{header}{Colors.RESET}")
        print("-" * 110)

        if horses_record:
            # 按總涉資本金降序排序顯示
            sorted_by_total = sorted(horses_record, key=lambda x: x["total_stake"], reverse=True)
            for h in sorted_by_total:
                dbl_str = f"${h['dbl_up_stake']/1000:.0f}K/${h['dbl_down_stake']/1000:.0f}K"
                line = (
                    f" {h['horse_no']:>3}  | "
                    f"{h['win_odds']:>7.1f}  | "
                    f"${h['win_stake']:>9,.0f} | "
                    f"${h['pla_stake']:>9,.0f} | "
                    f"${h['qin_exposure']:>9,.0f} | "
                    f"${h['qpl_exposure']:>9,.0f} | "
                    f"${h['tri_stake']:>8,.0f} | "
                    f"${h['tce_stake']:>9,.0f} | "
                    f"{dbl_str:>12} | "
                    f"{Colors.BOLD}${h['total_stake']:>10,.0f}{Colors.RESET}"
                )
                print(line)
        else:
            print("  \033[90m正在等待各分頁 WebSocket 數據流注入馬號與本金...\033[0m")

        print("-" * 110)
        print("📡 【實時進站封包流水】:")
        if SNIFFER_LOGS:
            for log in SNIFFER_LOGS:
                print(f"  \033[96m{log}\033[0m")
        else:
            print("  \033[90m等待 MQTT 封包中...\033[0m")
        print("=" * 110)
        print(f"{Colors.YELLOW}💡 提示：本腳本已開啟全頻道黑盒秒級錄影，隨時按 Ctrl+C 可安全保存並退出。{Colors.RESET}")

# ========================== 主程序 ==========================
async def main():
    global GLOBAL_RECORDER
    os.system("cls" if os.name == "nt" else "clear")

    print(f"{Colors.HEADER}{Colors.BOLD}========================================================================{Colors.RESET}")
    print(f"{Colors.HEADER}{Colors.BOLD}       🛰️  馬會 9 大彩池全量黑盒飛行記錄儀 (海外 / 本地獨立專用版)        {Colors.RESET}")
    print(f"{Colors.HEADER}{Colors.BOLD}========================================================================{Colors.RESET}")

    now_d = datetime.now().strftime("%Y-%m-%d")
    race_date = input(f"👉 請輸入賽事日期 (預設 {now_d}): ").strip() or now_d
    venue_in = input("👉 請輸入場地 (海外輸入 S1 / S2 / S3，本地輸入 ST / HV，預設 S1): ").strip().upper() or "S1"
    race_no_input = input("👉 請輸入場次 (預設 1): ").strip() or "1"
    target_race = int(race_no_input)
    prev_race = target_race - 1 if target_race > 1 else 0

    # 初始化黑盒錄影器
    GLOBAL_RECORDER = RaceFlightRecorder(race_date, venue_in, target_race)

    async with async_playwright() as p:
        print(f"\n[*] 正在啟動極速極簡 Chromium 引擎 (靜態資源攔截模式)...")
        browser = await p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-dev-shm-usage"
            ]
        )
        context = await browser.new_context()

        # 💡 極致效能優化：攔截所有圖片、字體、CSS，確保 8 個分頁秒開且 CPU/RAM 幾近零佔用
        await context.route(
            "**/*.{png,jpg,jpeg,gif,webp,svg,woff,woff2,ttf,eot,css}",
            lambda route: route.abort()
        )

        def on_web_socket(ws):
            if "hkjc.com" in ws.url:
                ws.on("framereceived", on_frame)

        def on_frame(data):
            packets = parse_mqtt_stream(data)
            for p_type, p_raw in packets:
                topic, text = process_packet(p_type, p_raw)
                if topic and text:
                    t_lower = topic.lower()
                    v_key = venue_in.lower()

                    race_tag_2d = f"/{v_key}/{target_race:02d}/"
                    race_tag_1d = f"/{v_key}/{target_race}/"
                    is_target_race = (race_tag_2d in t_lower) or (race_tag_1d in t_lower)

                    # 針對孖上 (Leg 2)，允許監聽上一場的 DBL 封包
                    is_prev_dbl = False
                    if prev_race > 0 and "/dbl/" in t_lower:
                        prev_tag_2d = f"/{v_key}/{prev_race:02d}/"
                        prev_tag_1d = f"/{v_key}/{prev_race}/"
                        if (prev_tag_2d in t_lower) or (prev_tag_1d in t_lower):
                            is_prev_dbl = True

                    # 海外與本地串流驗證
                    is_overseas = v_key.startswith("s") and len(v_key) >= 2 and v_key[1:].isdigit()
                    if not is_overseas:
                        is_valid_stream = not any(x in t_lower for x in ["/s1/", "/s2/", "/s3/"])
                    else:
                        is_valid_stream = True

                    if (is_target_race or is_prev_dbl) and is_valid_stream:
                        try:
                            data_json = json.loads(text)
                            dispatch_raw_packet(topic, data_json, target_race, prev_race)
                        except:
                            pass

        # 啟動實時儀表板與錄影協程
        asyncio.create_task(render_and_record_loop(race_date, venue_in, target_race))

        # 1. 循序掛載當前場次的 7 大核心彩池頁面
        for cfg in POOL_PAGE_CONFIG:
            target_url = f"https://bet.hkjc.com/ch/racing/{cfg['pool_id']}/{race_date}/{venue_in}/{target_race}"
            print(f"[*] 正在掛載彩池頁面 [{cfg['name']}]: {target_url}")
            try:
                page = await context.new_page()
                page.on("websocket", on_web_socket)
                await page.goto(target_url, timeout=25000, wait_until="domcontentloaded")
            except Exception as e:
                print(f"[-] 頁面載入逾時 ({cfg['pool_id']})，繼續掛載下一頁...")

        # 2. 若場次 > 1，額外掛載上一場的 DBL 頁面以啟動 Leg 2 (孖上) 訂閱
        if prev_race > 0:
            dbl_prev_url = f"https://bet.hkjc.com/ch/racing/dbl/{race_date}/{venue_in}/{prev_race}"
            print(f"[*] 正在掛載上一場孖寶頁面 (獲取孖上數據): {dbl_prev_url}")
            try:
                prev_page = await context.new_page()
                prev_page.on("websocket", on_web_socket)
                await prev_page.goto(dbl_prev_url, timeout=25000, wait_until="domcontentloaded")
            except Exception as e:
                print(f"[-] 上一場孖寶載入逾時，繼續監聽...")

        print(f"\n{Colors.BG_GREEN}{Colors.WHITE}{Colors.BOLD} [+] 全部分頁掛載完畢！所有 MQTT 彩池訂閱已激活，黑盒錄影進行中。 {Colors.RESET}")

        try:
            while True:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 收到終止訊號，正在關閉黑盒錄影器與瀏覽器...")
            if GLOBAL_RECORDER:
                GLOBAL_RECORDER.close()
            await browser.close()
            print("✅ 錄影檔已安全儲存！")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n程式已安全退出。")
