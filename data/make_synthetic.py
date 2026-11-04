"""Write a file of random bytes, used to measure hash throughput and latency by file size (NFR-02, NFR-03)."""
import argparse
import os

UNITS = {"K": 1 << 10, "M": 1 << 20, "G": 1 << 30}


def parse_size(s: str) -> int:
    s = s.strip().upper().rstrip("B")
    if s and s[-1] in UNITS:
        return int(float(s[:-1]) * UNITS[s[-1]])
    return int(s)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--size", required=True, help="e.g. 100M, 1G, 4G")
    p.add_argument("--out", required=True, help="output directory")
    args = p.parse_args()

    size = parse_size(args.size)
    os.makedirs(args.out, exist_ok=True)
    path = os.path.join(args.out, f"synthetic_{args.size.lower()}.bin")
    if os.path.exists(path) and os.path.getsize(path) == size:
        print(f"skip {path} (exists)")
        return
    chunk = 8 << 20
    with open(path + ".part", "wb") as f:
        left = size
        while left:
            n = min(chunk, left)
            f.write(os.urandom(n))
            left -= n
    os.replace(path + ".part", path)
    print(f"wrote {path} ({size} bytes)")


if __name__ == "__main__":
    main()
