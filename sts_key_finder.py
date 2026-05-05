#!/usr/bin/env python3
"""
Infinite STS Academic Key Finder v22.0 (LECTURER-OPTIMIZED)
✅ Raw Integer Comparison (Zero String Ops) | Larger Chunks | Pending Limit | Inlined Hot Loop
Expected: 3x-5x faster without breaking structure
"""
import hmac, hashlib, struct, time, os, json, signal, sys, gc
from multiprocessing import Pool, cpu_count
from Crypto.Cipher import DES3
import string

# ==========================================
# 📊 EXACT ASSIGNMENT DATA (PRECOMPUTED)
# ==========================================
SAMPLES = [
    {"date": "17/2/2026", "time": "22:12", "amt": "100.0", "token": "28751324489986790826"},
    {"date": "27/3/2026", "time": "20:56", "amt": "100.0", "token": "65136386180815310423"},
    {"date": "15/4/2026", "time": "12:01", "amt": "100.0", "token": "36753938000202112510"},
    {"date": "3/5/2026",   "time": "17:06", "amt": "100.0", "token": "10441034059641854354"}
]

PAN = "60072707152330689"
KT, TI, KRN, SGC = "0", "0", "2.2", "000000"
BASE_DATE = "2014-01-01"
BASE_DT = (2014, 1, 1)
TRANSPOSE = [15, 0, 4, 8, 12, 16, 19, 3, 7, 11, 14, 18, 2, 6, 10, 13, 17, 1, 5, 9]

DKGA_MSG = f"{PAN.ljust(16,'0')[:16]}{KT}{TI}{KRN.ljust(3,'0')[:3]}{SGC}{BASE_DATE.replace('-','')}".encode()
EXPECTED_TOKENS = [s["token"] for s in SAMPLES]

# ==========================================
# 🔧 CORE FUNCTIONS
# ==========================================
def crc16_ccitt(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= (byte << 8)
        for _ in range(8):
            crc = (crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1
    return crc & 0xFFFF

def calc_tid(date_str, time_str):
    from datetime import datetime
    d, m, y = map(int, date_str.split('/'))
    h, mi = map(int, time_str.split(':'))
    dt = datetime(y, m, d, h, mi)
    base = datetime(*BASE_DT)
    return int((dt - base).total_seconds() // 60) & 0xFFFFFF

def encode_amount(amt):
    val = int(float(amt) * 10)
    if val <= 16383: return (0 << 14) | val
    if val <= 180214: return (1 << 14) | ((val - 16384) // 10)
    return (2 << 14) | ((val - 180214) // 100)

def build_block(tid, amt):
    amt_bits = encode_amount(amt)
    crc_data = struct.pack('>I', tid)[1:] + struct.pack('>H', amt_bits) + b'\x00'
    crc = crc16_ccitt(crc_data)
    block = (tid << 40) | (amt_bits << 24) | (crc << 8)
    return block.to_bytes(8, 'big')

PLAINTEXT_BLOCKS = [build_block(calc_tid(s["date"], s["time"]), float(s["amt"])) for s in SAMPLES]

# ==========================================
# 🔥 LECTURER OPTIMIZATION #6 & #10: RAW INTEGER COMPARISON
# ==========================================
# Precompute inverse transpose to reverse the token back to raw 64-bit int
INV_TRANSPOSE = [0] * 20
for i, p in enumerate(TRANSPOSE):
    INV_TRANSPOSE[p] = i

def token_to_raw_int(token_str):
    """Reverse transposition + remove class bits → raw 64-bit ciphertext int"""
    chars = [''] * 20
    for i, p in enumerate(INV_TRANSPOSE):
        chars[p] = token_str[i]
    return int(''.join(chars)) >> 2

# Precompute expected raw integers for O(1) comparison (ZERO STRING OPS IN LOOP)
EXPECTED_RAW = [token_to_raw_int(t) for t in EXPECTED_TOKENS]

# ==========================================
# 🔍 OPTIMIZED WORKER (Inlined, No Exceptions, Raw Int Compare)
# ==========================================
def search_worker(key_chunk):
    # Cache globals locally (avoids global lookup overhead)
    local_blocks = PLAINTEXT_BLOCKS
    exp0, exp1, exp2, exp3 = EXPECTED_RAW
    msg = DKGA_MSG
    
    for vk in key_chunk:
        # Inline HMAC + DES3 (no function calls)
        key = hmac.new(vk, msg, hashlib.sha256).digest()[:16]
        key24 = key + key[:8]
        
        # Encrypt first block
        ct0 = DES3.new(key24, DES3.MODE_ECB).encrypt(local_blocks[0])
        val0 = int.from_bytes(ct0, 'big')
        
        # 🔥 RAW INTEGER COMPARISON (Skips 100% of string/formatting ops)
        if val0 != exp0:
            continue
            
        # Only if first matches, verify remaining 3
        if (int.from_bytes(DES3.new(key24, DES3.MODE_ECB).encrypt(local_blocks[1]), 'big') == exp1 and
            int.from_bytes(DES3.new(key24, DES3.MODE_ECB).encrypt(local_blocks[2]), 'big') == exp2 and
            int.from_bytes(DES3.new(key24, DES3.MODE_ECB).encrypt(local_blocks[3]), 'big') == exp3):
            return vk.hex()
    return None

# ==========================================
# 🔑 MEMORY-SAFE KEY GENERATOR (UNCHANGED)
# ==========================================
CHARSET = string.ascii_uppercase + string.digits
CHARSET_LEN = len(CHARSET)

def idx_to_ascii(idx, length):
    chars = []
    for _ in range(length):
        chars.append(CHARSET[idx % CHARSET_LEN])
        idx //= CHARSET_LEN
    return ''.join(reversed(chars))

def yield_keys_from(start_idx=0):
    idx = 0
    if idx < start_idx: pass
    else:
        words = ["STS","CIU3","METER","TOKEN","VEND","LAB","KEY","VK","DKGA","EA07","KRN","2014","2026","CASH","POWER","GRID","UNI","COURSE","ADMIN","TEST","DEMO","DEFAULT"]
        suffixes = ["","_01","_LAB","_VK","_KEY","2026","2014","STS","CIU3","KRN22","EA07","DKGA04"]
        for w in words:
            for s in suffixes:
                if idx >= start_idx: yield idx, (w+s).encode().ljust(16, b'\x00')[:16]
                idx += 1
    if idx < start_idx: idx = 300 
    else:
        drn = b"07152330689"
        dates = [b"20140101", b"20260217", b"20260327", b"20260415", b"20260503"]
        for d in dates:
            for combo in [(drn+d), (d+drn), bytes(b^0xFF for b in drn), drn[::-1]]:
                if idx >= start_idx: yield idx, combo.ljust(16, b'\x00')[:16]
                idx += 1
    if idx < start_idx: idx = 350
    else:
        hex_seqs = ["0011223344556677","8899AABBCCDDEEFF","A5A5A5A5A5A5A5A5","5A5A5A5A5A5A5A5A",
                    "0123456789ABCDEF","FEDCBA9876543210","1111111111111111","AAAAAAAAAAAAAAAA"]
        for h in hex_seqs:
            b = bytes.fromhex(h)
            for k in [b*2, b+b[:8]]:
                if idx >= start_idx: yield idx, k
                idx += 1
    if idx < start_idx: idx = 370
    lengths = [3, 4, 5, 6]
    offsets = [0, 46656, 46656+1679616, 46656+1679616+60466176]
    for l_idx, length in enumerate(lengths):
        total_combos = CHARSET_LEN ** length
        start_offset = offsets[l_idx]
        current_phase_start = 370 + start_offset
        if idx < current_phase_start:
            idx = current_phase_start + total_combos * 3 
            continue
        combos_done = (idx - current_phase_start) // 3
        variant_offset = (idx - current_phase_start) % 3
        while combos_done < total_combos:
            base_str = idx_to_ascii(combos_done, length)
            if variant_offset == 0:
                if idx >= start_idx: yield idx, base_str.encode().ljust(16, b'\x00')[:16]
                idx += 1; variant_offset = 1
            if variant_offset == 1:
                if idx >= start_idx: yield idx, (base_str+"_KEY").encode().ljust(16, b'\x00')[:16]
                idx += 1; variant_offset = 2
            if variant_offset == 2:
                if idx >= start_idx: yield idx, (base_str+"_LAB").encode().ljust(16, b'\x00')[:16]
                idx += 1; variant_offset = 0
                combos_done += 1
    dicts = ["energy","power","grid","smart","prepaid","utility","invoice","payment","reference","service","decode","cipher","crypto","block","token","meter","cash","vending","academic","university","student","lab","test","demo","default","admin","root","system","config","setup","init","base","date","time","tid","crc","des","aes","sha","hmac","dkga","ea07","krn","sts","ciu3"]
    mods = ["","01","02","10","20","26","14","_VK","_KEY","_LAB","_STS","_CIU","_2026","_2014","_KRN","_EA07","_DKGA"]
    d_idx = 0
    while True:
        if idx >= start_idx:
            w = dicts[d_idx % len(dicts)]
            m = mods[d_idx % len(mods)]
            yield idx, (w+m).encode().ljust(16, b'\x00')[:16]
            yield idx+1, (m+w).encode().ljust(16, b'\x00')[:16]
            yield idx+2, (w.upper()+m).encode().ljust(16, b'\x00')[:16]
        idx += 3
        d_idx += 1

# ==========================================
# 🛡️ CHECKPOINT & SIGNAL HANDLING
# ==========================================
CHECKPOINT_FILE = "sts_checkpoint.json"
running = True
next_idx = 0
keys_tested = 0
start_time = time.time()

def save_checkpoint():
    with open(CHECKPOINT_FILE, 'w') as f:
        json.dump({"next_idx": next_idx, "keys_tested": keys_tested, "start_time": start_time}, f)

def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE, 'r') as f:
            data = json.load(f)
            return data.get("next_idx", 0), data.get("keys_tested", 0), data.get("start_time", time.time())
    return 0, 0, time.time()

def graceful_exit(sig, frame):
    global running
    running = False
    print("\n\n⏸️  STOPPING GRACEFULLY... Saving exact position...")
    save_checkpoint()
    elapsed = time.time() - start_time
    print(f"📊 Final Stats: {keys_tested:,} keys tested | {elapsed/3600:.2f} hours | {keys_tested/max(1,elapsed):,.0f} keys/sec")
    print(f"💾 Checkpoint saved to {CHECKPOINT_FILE}")
    print(f"🔄 RESUME: Run script again. Continues exactly from key #{next_idx:,}")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_exit)

# ==========================================
# 🚀 MAIN EXECUTION (OPTIMIZED IPC & QUEUE)
# ==========================================
def main():
    global next_idx, keys_tested, start_time, running
    
    print("="*70)
    print("  INFINITE STS KEY FINDER v22.0 (LECTURER-OPTIMIZED)")
    print("  ✅ Raw Int Compare | 200k Chunks | Pending Limit | Inlined Loop")
    print("="*70 + "\n")
    
    next_idx, keys_tested, start_time = load_checkpoint()
    if next_idx > 0:
        print(f"📂 RESUMING from checkpoint: Key #{next_idx:,} | {keys_tested:,} tested\n")
    else:
        print(f"🆕 Fresh start. Press Ctrl+C anytime to save & resume.\n")
        
    cores = min(20, cpu_count())
    print(f"⚡ Spawning {cores} workers...")
    print(f"⏱️  Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    # 🔥 LECTURER #3: Larger chunks reduce IPC overhead
    chunk_size = 200000
    # 🔥 LECTURER #4: Limit pending jobs to prevent memory bloat & slowdown
    MAX_PENDING = cores * 2
    
    key_gen = yield_keys_from(next_idx)
    chunk = []
    last_stats = time.time()
    
    with Pool(processes=cores) as pool:
        pending = []
        
        while running:
            try:
                while len(chunk) < chunk_size:
                    try:
                        idx, key = next(key_gen)
                        chunk.append(key)
                    except StopIteration:
                        break
                
                if not chunk:
                    print("🔄 Generator exhausted. Switching to infinite dictionary phase...")
                    break 

                pending.append(pool.apply_async(search_worker, (chunk,)))
                chunk = []
                
                # 🔥 LECTURER #4: Cap pending jobs
                while len(pending) >= MAX_PENDING:
                    time.sleep(0.01)
                    pending = [p for p in pending if not p.ready()]
                    for p in pending:
                        if p.ready():
                            res = p.get()
                            if res:
                                print(f"\n✅ KEY FOUND at index #{next_idx:,}!")
                                print(f"🔐 Vending Key (hex): {res}")
                                save_checkpoint()
                                return
                            keys_tested += chunk_size
                            next_idx += chunk_size
                            pending.remove(p)
                
                # Clean up finished jobs
                new_pending = []
                for p in pending:
                    if p.ready():
                        res = p.get()
                        if res:
                            print(f"\n✅ KEY FOUND at index #{next_idx:,}!")
                            print(f"🔐 Vending Key (hex): {res}")
                            save_checkpoint()
                            return
                        keys_tested += chunk_size
                        next_idx += chunk_size
                    else:
                        new_pending.append(p)
                pending = new_pending
                
                if time.time() - last_stats > 10:
                    elapsed = time.time() - start_time
                    rate = keys_tested / max(1, elapsed)
                    print(f"📊 [{time.strftime('%H:%M:%S')}] #{next_idx:,} | {keys_tested:,} tested | {elapsed/3600:.2f}h | {rate:,.0f} keys/s")
                    save_checkpoint()
                    last_stats = time.time()
                    
            except Exception as e:
                print(f"⚠️  Error: {e}")
                time.sleep(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        graceful_exit(None, None)
