#!/usr/bin/env python3
"""
RealVul Dataset Preparation Script for PDBERT
==============================================
호스트에서 실행하면 docker cp로 스크립트를 컨테이너에 복사 후 실행합니다.
컨테이너 내부에서도 직접 실행 가능합니다.

Usage:
    python prepare_dataset.py --path <dataset_path>

Dataset Paths:
    realvul/<project>       # 학습용 데이터셋
    realvul_test/<project>  # 테스트용 데이터셋

Projects:
    Chrome, FFmpeg, ImageMagick, jasper, krb5, linux, openssl, php-src, qemu, tcpdump
    Real_Vul (전체 통합)

Examples:
    docker exec pdbert python /PDBERT/prepare_dataset.py --path realvul/jasper
    docker exec pdbert python /PDBERT/prepare_dataset.py --path realvul_test/Real_Vul
"""

import csv
import json
import tarfile
import random
import argparse
import subprocess
import sys
import os
from pathlib import Path


AVAILABLE_PROJECTS = [
    "Chrome", "FFmpeg", "ImageMagick", "jasper", "krb5",
    "linux", "openssl", "php-src", "qemu", "tcpdump", "Real_Vul"
]

BASE_DIR = "/PDBERT/data/datasets/extrinsic/vul_detect"
CONTAINER_NAME = "pdbert"
CONTAINER_SCRIPT_PATH = "/PDBERT/prepare_dataset.py"


def is_in_container() -> bool:
    """Check if running inside container."""
    return os.path.exists('/.dockerenv') or os.path.exists('/PDBERT')


def extract_source_code(tar_path: Path, extract_dir: Path) -> bool:
    """Extract source code from tar archive."""
    if not tar_path.exists():
        print(f"[ERROR] Archive not found: {tar_path}")
        return False
    
    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"[INFO] Source already extracted: {extract_dir}")
        return True
    
    print(f"[INFO] Extracting {tar_path}...")
    try:
        with tarfile.open(tar_path, 'r:*') as tar:
            tar.extractall(path=tar_path.parent)
        print("[INFO] Extraction complete.")
        return True
    except tarfile.ReadError:
        pass
    
    try:
        with tarfile.open(tar_path, 'r:') as tar:
            tar.extractall(path=tar_path.parent)
        print("[INFO] Extraction complete (plain tar).")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to extract: {e}")
        return False


def convert_to_json(csv_path: Path, source_dir: Path, output_dir: Path,
                   file_name_key: str = 'file_name', file_extension: str = '') -> dict:
    """Convert CSV dataset to JSON format for PDBERT."""
    if not csv_path.exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        return {}
    
    if not source_dir.exists():
        print(f"[ERROR] Source directory not found: {source_dir}")
        return {}
    
    random.seed(42)
    train_val_data, test_data = [], []
    stats = {"total": 0, "found": 0, "not_found": 0, "empty": 0, "vul": 0, "non_vul": 0}
    
    print(f"[INFO] Reading CSV: {csv_path}")
    with open(csv_path, 'r', encoding='utf-8') as f:
        for row in csv.DictReader(f):
            stats["total"] += 1
            
            source_file = source_dir / (row[file_name_key] + file_extension)
            if not source_file.exists():
                stats["not_found"] += 1
                continue
            
            code = open(source_file, 'r', errors='ignore').read()
            if not code.strip():
                stats["empty"] += 1
                continue
            
            stats["found"] += 1
            vul = 1 if row['vulnerable_line_numbers'].strip() else 0
            stats["vul" if vul else "non_vul"] += 1
            
            item = {"code": code, "vul": vul}
            (train_val_data if row['dataset_type'] == "train_val" else test_data).append(item)
    
    random.shuffle(train_val_data)
    split_idx = int(len(train_val_data) * 0.8)
    train_data, validate_data = train_val_data[:split_idx], train_val_data[split_idx:]
    
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in [("train", train_data), ("validate", validate_data), ("test", test_data)]:
        with open(output_dir / f"{name}.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"[INFO] Created: {output_dir / f'{name}.json'}")
    
    return {"train": len(train_data), "validate": len(validate_data), "test": len(test_data), "stats": stats}


def print_summary(project: str, result: dict, base_dir: Path):
    """Print summary."""
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Project:     {project}")
    print(f"  Output:      {base_dir}")
    print(f"  Train:       {result['train']} samples")
    print(f"  Validate:    {result['validate']} samples")
    print(f"  Test:        {result['test']} samples")
    print(f"  ---")
    s = result['stats']
    print(f"  Total: {s['total']}, Found: {s['found']}, NotFound: {s['not_found']}, Empty: {s['empty']}")
    print(f"  Vulnerable: {s['vul']}, Non-vulnerable: {s['non_vul']}")
    print("=" * 60)
    print("Done!")


def process_project(project: str, base_dir: Path) -> int:
    """Process dataset for a project."""
    print("=" * 60)
    print(f"RealVul Dataset Preparation for PDBERT")
    print(f"  Project: {project}")
    print(f"  Output:  {base_dir}")
    print("=" * 60)
    
    if project == "Real_Vul":
        csv_path = base_dir / "Real_Vul_data.csv"
        source_dir = base_dir / "all_source_code"
        file_ext = ".c"
    else:
        csv_path = base_dir / f"{project}_dataset.csv"
        source_dir = base_dir / "source_code"
        tar_path = base_dir / f"{project}_source_code.tar.gz"
        file_ext = ""
        if not extract_source_code(tar_path, source_dir):
            return 1
    
    if not source_dir.exists():
        print(f"[ERROR] Source directory not found: {source_dir}")
        return 1
    
    result = convert_to_json(csv_path, source_dir, base_dir, file_extension=file_ext)
    if not result:
        return 1
    
    print_summary(project, result, base_dir)
    return 0


def run_in_container(dataset_path: str) -> int:
    """Copy script to container and execute."""
    script_path = Path(__file__).resolve()
    
    # docker cp
    print(f"[INFO] Copying script to container...")
    cp_result = subprocess.run(
        ["docker", "cp", str(script_path), f"{CONTAINER_NAME}:{CONTAINER_SCRIPT_PATH}"],
        capture_output=True, text=True
    )
    if cp_result.returncode != 0:
        print(f"[ERROR] Failed to copy script: {cp_result.stderr}")
        return 1
    
    # docker exec
    print(f"[INFO] Executing in container '{CONTAINER_NAME}'...")
    print("-" * 60)
    
    exec_result = subprocess.run(
        ["docker", "exec", CONTAINER_NAME, "python3", CONTAINER_SCRIPT_PATH, "--path", dataset_path],
        text=True
    )
    return exec_result.returncode


def check_container_running() -> bool:
    """Check if container is running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER_NAME],
            capture_output=True, text=True, timeout=10
        )
        return result.stdout.strip() == "true"
    except:
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Prepare RealVul dataset for PDBERT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    docker exec pdbert python /PDBERT/prepare_dataset.py --path realvul/jasper
    docker exec pdbert python /PDBERT/prepare_dataset.py --path realvul_test/Real_Vul
        """
    )
    parser.add_argument(
        "--path", 
        required=True,
        help="Dataset path: realvul/<project> or realvul_test/<project>"
    )
    
    args = parser.parse_args()
    
    # Parse dataset path: realvul/jasper -> (realvul, jasper)
    path_parts = args.path.strip('/').split('/')
    if len(path_parts) != 2:
        print(f"[ERROR] Invalid path format: {args.path}")
        print("[INFO] Expected format: realvul/<project> or realvul_test/<project>")
        return 1
    
    dataset_type, project = path_parts
    
    if dataset_type not in ["realvul", "realvul_test"]:
        print(f"[ERROR] Invalid dataset type: {dataset_type}")
        print("[INFO] Must be 'realvul' or 'realvul_test'")
        return 1
    
    if project not in AVAILABLE_PROJECTS:
        print(f"[ERROR] Invalid project: {project}")
        print(f"[INFO] Available: {', '.join(AVAILABLE_PROJECTS)}")
        return 1
    
    full_path = f"{BASE_DIR}/{dataset_type}/{project}" if project != "Real_Vul" else f"{BASE_DIR}/{dataset_type}"
    
    if is_in_container():
        # Running inside container - execute directly
        return process_project(project, Path(full_path))
    else:
        # Running on host - copy and execute in container
        print("=" * 60)
        print("RealVul Dataset Preparation for PDBERT (Host)")
        print(f"  Dataset Path: {args.path}")
        print(f"  Full Path:    {full_path}")
        print("=" * 60)
        
        if not check_container_running():
            print(f"[ERROR] Container '{CONTAINER_NAME}' is not running.")
            print("[INFO] Start with: docker compose up -d pdbert")
            return 1
        
        return run_in_container(args.path)


if __name__ == "__main__":
    sys.exit(main())
