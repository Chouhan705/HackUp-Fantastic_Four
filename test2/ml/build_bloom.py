import csv
import json
import mmh3
import math
import os

def build_bloom_filter(csv_path, output_path, n_domains=10000, error_rate=0.01):
    print(f"Reading top {n_domains} domains from {csv_path}...")
    
    # Calculate optimal Bloom filter size
    m = math.ceil((n_domains * math.log(error_rate)) / math.log(1 / math.pow(2, math.log(2))))
    m = int(m)
    k = max(1, round((m / n_domains) * math.log(2)))
    
    # Needs to be a bit array
    bit_array = [0] * m
    
    domains_added = 0
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        for i, row in enumerate(reader):
            if domains_added >= n_domains:
                break
            # CSV usually has rank, domain (e.g. Cisco Umbrella or Tranco)
            if len(row) >= 2:
                domain = row[1].strip().lower()
            else:
                domain = row[0].strip().lower()
            
            # Hash
            for seed in range(k):
                # Using MurmurHash3 (32-bit unsigned), same as JS library
                digest = mmh3.hash(domain, seed, signed=False)
                bit_array[digest % m] = 1
            
            domains_added += 1

    print(f"Bloom filter size: {m} bits, hash functions: {k}")
    
    # Pack the bits into integers to save space in the JSON payload
    packed = []
    for i in range(0, m, 32):
        chunk = bit_array[i:i+32]
        val = 0
        for bit_idx, bit in enumerate(chunk):
            if bit:
                val |= (1 << bit_idx)
        packed.append(val)
    
    data = {
        "m": m,
        "k": k,
        "data": packed
    }

    with open(output_path, 'w') as f:
        json.dump(data, f)
    
    # Print the file size
    size_kb = os.path.getsize(output_path) / 1024
    print(f"Exported bloom filter to {output_path} (File size: {size_kb:.2f} KB)")

if __name__ == "__main__":
    build_bloom_filter("NoPhishZone/dataset/top-1m.csv", "NoPhishZone/bloom.json")
