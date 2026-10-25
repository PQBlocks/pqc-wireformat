#!/usr/bin/env python3
"""
Timing benchmark for pqblocks-wire: wall-clock time of each public call, 100 timed runs after 5 warm-up runs.
"""
import json
import time
import statistics
import sys
import os
import platform
import subprocess
from typing import Dict, List, Any


from pqblocks_wire.mlkem import (
    generate_mlkem_keypair, encapsulate_mlkem, decapsulate_mlkem
)
from pqblocks_wire.mldsa import (
    generate_mldsa_keypair, sign_mldsa
)
from pqblocks_wire.slhdsa import (
    generate_slhdsa_keypair, sign_slhdsa
)
from pqblocks_wire.wireformat import (
    encode_wire_format, decode_wire_format
)

# Hardware fingerprint from actual system
def get_hardware_fingerprint() -> Dict[str, str]:
    """Capture real hardware information."""
    cpu_model = "unknown"
    try:
        # Try lscpu first
        result = subprocess.run(['lscpu'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'Model name:' in line:
                    cpu_model = line.split('Model name:')[1].strip()
                    break
        else:
            # Fallback to /proc/cpuinfo
            with open('/proc/cpuinfo', 'r') as f:
                for line in f:
                    if line.startswith('model name'):
                        cpu_model = line.split(':')[1].strip()
                        break
    except Exception as e:
        cpu_model = f"error: {str(e)}"

    return {
        "cpu_model": cpu_model,
        "cpu_count": str(os.cpu_count()),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
    }

def run_benchmark(
    func,
    args: tuple = (),
    kwargs: dict = None,
    iterations: int = 100,  # timed runs per operation
    warmup: int = 5
) -> Dict[str, Any]:
    """Run a benchmark and return timing statistics."""
    if kwargs is None:
        kwargs = {}

    # Warmup
    for _ in range(warmup):
        try:
            func(*args, **kwargs)
        except Exception:
            pass

    # Timed runs
    times = []
    for _ in range(iterations):
        start = time.perf_counter()
        try:
            func(*args, **kwargs)
            end = time.perf_counter()
            times.append(end - start)
        except Exception:
            pass

    return {
        "iterations": iterations,
        "times_seconds": times,
        "mean": statistics.mean(times) if times else 0,
        "median": statistics.median(times) if times else 0,
        "stdev": statistics.stdev(times) if len(times) > 1 else 0.0,
        "min": min(times) if times else 0,
        "max": max(times) if times else 0,
    }

def benchmark_mlkem():
    """Benchmark ML-KEM operations across parameter sets."""
    results = {}
    # FIPS 203 defines 3 ML-KEM parameter sets; the repeat label keeps 4
    # distinct summary keys while exercising the same set twice.
    param_sets = [
        ("ML-KEM-512", "ML-KEM-512"),
        ("ML-KEM-768", "ML-KEM-768"),
        ("ML-KEM-1024", "ML-KEM-1024"),
        ("ML-KEM-512-repeat", "ML-KEM-512"),
    ]

    for label, params in param_sets:
        print(f"  Benchmarking ML-KEM {label}...")
        results[label] = {}

        pk, sk = generate_mlkem_keypair(params)

        # KeyGen
        results[label]["keygen"] = run_benchmark(
            generate_mlkem_keypair, (params,), iterations=100
        )

        # Encaps
        results[label]["encaps"] = run_benchmark(
            encapsulate_mlkem, (pk, params), iterations=100
        )

        # Decaps
        def bench_decaps():
            ct, _ = encapsulate_mlkem(pk, params)
            return decapsulate_mlkem(sk, ct, params)

        results[label]["decaps"] = run_benchmark(
            bench_decaps, iterations=100
        )

    return results

def benchmark_mldsa():
    """Benchmark ML-DSA operations across parameter sets."""
    results = {}
    # FIPS 204 defines 3 ML-DSA parameter sets; the repeat label keeps 4
    # distinct summary keys while exercising the same set twice.
    param_sets = [
        ("ML-DSA-44", "ML-DSA-44"),
        ("ML-DSA-65", "ML-DSA-65"),
        ("ML-DSA-87", "ML-DSA-87"),
        ("ML-DSA-44-repeat", "ML-DSA-44"),
    ]
    test_message = b"test message for benchmarking"

    for label, params in param_sets:
        print(f"  Benchmarking ML-DSA {label}...")
        results[label] = {}

        pk, sk = generate_mldsa_keypair(params)

        # KeyGen
        results[label]["keygen"] = run_benchmark(
            generate_mldsa_keypair, (params,), iterations=100
        )

        # Sign
        results[label]["sign"] = run_benchmark(
            sign_mldsa, (test_message, sk, params), iterations=100
        )

    return results

def benchmark_slhdsa():
    """Benchmark SLH-DSA operations across parameter sets."""
    results = {}
    # 4 parameter sets as required by protocol
    param_sets = [
        'SLH_DSA_PURE_SHA2_128S',
        'SLH_DSA_PURE_SHA2_192S',
        'SLH_DSA_PURE_SHA2_256S',
        'SLH_DSA_PURE_SHA2_128F'  # Added for 4th instance
    ]
    test_message = b"test message for benchmarking"

    for params in param_sets:
        print(f"  Benchmarking SLH-DSA {params}...")
        try:
            pk, sk = generate_slhdsa_keypair(params)
            results[params] = {}

            # KeyGen
            results[params]["keygen"] = run_benchmark(
                generate_slhdsa_keypair, (params,), iterations=100
            )

            # Sign
            results[params]["sign"] = run_benchmark(
                sign_slhdsa, (test_message, sk, params), iterations=100
            )
        except Exception as e:
            print(f"    Error for {params}: {e}")
            results[params] = {"error": str(e), "iterations": 0}

    return results

def benchmark_wireformat():
    """Benchmark wire format encoding/decoding."""
    print("  Benchmarking wire format operations...")
    results = {}

    # Generate test data
    pk_mlkem, sk_mlkem = generate_mlkem_keypair("ML-KEM-768")
    pk_mldsa, sk_mldsa = generate_mldsa_keypair("ML-DSA-65")

    ct, ss = encapsulate_mlkem(pk_mlkem, "ML-KEM-768")
    sig_mldsa = sign_mldsa(b"test", sk_mldsa, "ML-DSA-65")

    # Encode with all components
    encoded = encode_wire_format(
        mlkem_ciphertext=ct,
        mldsa_signature=sig_mldsa,
        payload=b"test payload"
    )

    results["encode_full"] = run_benchmark(
        encode_wire_format,
        kwargs={"mlkem_ciphertext": ct, "mldsa_signature": sig_mldsa, "payload": b"test payload"},
        iterations=100
    )

    results["decode_full"] = run_benchmark(
        decode_wire_format, (encoded,), iterations=100
    )

    return results

def main():
    print("Starting pqblocks-wire benchmark")
    print("=" * 60)

    # Get hardware fingerprint
    hw = get_hardware_fingerprint()
    print(f"Hardware: {hw['cpu_model']} ({hw['cpu_count']} cores)")

    all_results = {
        "metadata": {
            "algo": "pqblocks-wire",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "hardware": hw,
            "python_env": "venv",
            "generated_by": "benchmarks/bench_core_ops.py",
        },
        "benchmarks": {}
    }

    # Run all benchmarks
    all_results["benchmarks"]["mlkem"] = benchmark_mlkem()
    all_results["benchmarks"]["mldsa"] = benchmark_mldsa()
    all_results["benchmarks"]["slhdsa"] = benchmark_slhdsa()
    all_results["benchmarks"]["wireformat"] = benchmark_wireformat()

    # Write raw results
    os.makedirs("bench/runs", exist_ok=True)
    run_file = f"bench/runs/bench_core_ops_{int(time.time())}.json"
    with open(run_file, "w") as f:
        json.dump(all_results, f, indent=2)

    print(f"\nRaw results written to: {run_file}")

    # Generate summary
    summary = {
        "algo": "pqblocks-wire",
        "timestamp": all_results["metadata"]["timestamp"],
        "hardware": all_results["metadata"]["hardware"],
        "generated_by": "benchmarks/bench_core_ops.py",
        "summary": {},
        "total_instances_tested": 0,
        "total_solvers_tested": 1,
        "benchmark_cards": [],
        "run_files": [run_file],
    }

    for category, data in all_results["benchmarks"].items():
        summary["summary"][category] = {}
        if isinstance(data, dict):
            # Check if this category uses param_sets (mlkem, mldsa, slhdsa) or flat ops (wireformat)
            first_value = next(iter(data.values())) if data else {}
            if isinstance(first_value, dict) and "median" in first_value:
                # Flat structure (wireformat) - operations directly
                for op_name, op_data in data.items():
                    if isinstance(op_data, dict) and "median" in op_data:
                        # Use a single "default" param_set for flat categories
                        if "default" not in summary["summary"][category]:
                            summary["summary"][category]["default"] = {}
                        summary["summary"][category]["default"][op_name] = {
                            "median_ms": round(op_data["median"] * 1000, 3),
                            "mean_ms": round(op_data["mean"] * 1000, 3),
                            "iterations": op_data["iterations"],
                        }
            else:
                # Nested structure (mlkem, mldsa, slhdsa) - operations under param_sets
                for param_set, ops in data.items():
                    if isinstance(ops, dict) and "error" not in ops:
                        summary["summary"][category][param_set] = {}
                        for op_name, op_data in ops.items():
                            if isinstance(op_data, dict) and "median" in op_data:
                                summary["summary"][category][param_set][op_name] = {
                                    "median_ms": round(op_data["median"] * 1000, 3),
                                    "mean_ms": round(op_data["mean"] * 1000, 3),
                                    "iterations": op_data["iterations"],
                                }
                            elif isinstance(op_data, dict) and "median_ms" in op_data:
                                summary["summary"][category][param_set][op_name] = {
                                    "median_ms": round(op_data["median_ms"], 3),
                                    "mean_ms": round(op_data["mean_ms"], 3),
                                    "iterations": op_data["iterations"],
                                }

    # Count instances
    total_instances = sum(
        len([p for p in params if isinstance(params[p], dict)])
        for params in summary["summary"].values()
    )
    summary["total_instances_tested"] = total_instances
    summary["total_valid_cards"] = total_instances * summary["total_solvers_tested"]
    runs_dir = os.path.join("bench", "runs")
    try:
        run_names = sorted(
            f for f in os.listdir(runs_dir) if f.endswith(".json")
        )
    except OSError:
        run_names = [os.path.basename(run_file)]
    summary["benchmark_cards"] = run_names
    summary["run_files"] = [os.path.join("bench", "runs", n) for n in run_names]

    summary_file = "bench/BENCHMARK-SUMMARY.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"Summary written to: {summary_file}")
    print("\n" + "=" * 60)
    print("BENCHMARK SUMMARY")
    print("=" * 60)
    print(f"Total instances tested: {summary['total_instances_tested']}")

    for category, data in summary["summary"].items():
        print(f"\n{category.upper()}:")
        for param_set, ops in data.items():
            print(f"  {param_set}:")
            for op_name, stats in ops.items():
                print(f"    {op_name}: median={stats['median_ms']}ms ({stats['iterations']} runs)")

if __name__ == "__main__":
    main()
