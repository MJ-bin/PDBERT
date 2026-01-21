#!/usr/bin/env python3
"""
RealVul Dataset Preparation Script for PDBERT
==============================================
호스트에서 실행하면 docker cp로 스크립트를 컨테이너에 복사 후 실행합니다.
컨테이너 내부에서도 직접 실행 가능합니다.

Usage:
    python prepare_dataset.py --path <absolute_dataset_path> [--output <output_path>]

Examples:
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul/jasper
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul/jasper --output /PDBERT/output/jasper
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul_test/Real_Vul --output /PDBERT/output/real_vul
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
from typing import Optional, Tuple, Dict

# CSV 필드 크기 제한 해제 (processed_func에 큰 코드가 있을 수 있음)
csv.field_size_limit(sys.maxsize)


AVAILABLE_PROJECTS = [
    "Chrome", "FFmpeg", "ImageMagick", "jasper", "krb5",
    "linux", "openssl", "php-src", "qemu", "tcpdump", "Real_Vul"
]

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
    """Convert CSV dataset to JSON format for PDBERT (with source code mapping)."""
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


def convert_to_json_from_csv(csv_path: Path, output_dir: Path) -> dict:
    """Convert CSV dataset to JSON format using processed_func column directly."""
    if not csv_path.exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        return {}
    
    random.seed(42)
    train_val_data, test_data = [], []
    stats = {"total": 0, "valid": 0, "empty": 0, "vul": 0, "non_vul": 0}
    
    print(f"[INFO] Reading CSV (using processed_func column): {csv_path}")
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        
        # Check if processed_func column exists
        if 'processed_func' not in reader.fieldnames:
            print(f"[ERROR] 'processed_func' column not found in CSV")
            print(f"[INFO] Available columns: {reader.fieldnames}")
            print(f"[INFO] Use --add-processed-func option to map from source files")
            return {}
        
        for row in reader:
            stats["total"] += 1
            
            code = row.get('processed_func', '').strip()
            if not code:
                stats["empty"] += 1
                continue
            
            stats["valid"] += 1
            vul = 1 if row.get('vulnerable_line_numbers', '').strip() else 0
            stats["vul" if vul else "non_vul"] += 1
            
            item = {"code": code, "vul": vul}
            dataset_type = row.get('dataset_type', 'train_val')
            (train_val_data if dataset_type == "train_val" else test_data).append(item)
    
    random.shuffle(train_val_data)
    split_idx = int(len(train_val_data) * 0.8)
    train_data, validate_data = train_val_data[:split_idx], train_val_data[split_idx:]
    
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, data in [("train", train_data), ("validate", validate_data), ("test", test_data)]:
        with open(output_dir / f"{name}.json", 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
        print(f"[INFO] Created: {output_dir / f'{name}.json'} ({len(data)} samples)")
    
    return {"train": len(train_data), "validate": len(validate_data), "test": len(test_data), "stats": stats}


def print_summary(project: str, result: dict, input_dir: Path, output_dir: Path):
    """Print summary."""
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Project:     {project}")
    print(f"  Input:       {input_dir}")
    print(f"  Output:      {output_dir}")
    print(f"  Train:       {result['train']} samples")
    print(f"  Validate:    {result['validate']} samples")
    print(f"  Test:        {result['test']} samples")
    print(f"  ---")
    s = result['stats']
    # convert_to_json uses 'found', convert_to_json_from_csv uses 'valid'
    if 'found' in s:
        print(f"  Total: {s['total']}, Found: {s['found']}, NotFound: {s['not_found']}, Empty: {s['empty']}")
    else:
        print(f"  Total: {s['total']}, Valid: {s['valid']}, Empty: {s['empty']}")
    print(f"  Vulnerable: {s['vul']}, Non-vulnerable: {s['non_vul']}")
    print("=" * 60)
    print("Done!")


def process_project(project: str, input_dir: Path, output_dir: Path, add_processed_func: bool = False) -> int:
    """Process dataset for a project."""
    print("=" * 60)
    print(f"RealVul Dataset Preparation for PDBERT")
    print(f"  Project: {project}")
    print(f"  Input:   {input_dir}")
    print(f"  Output:  {output_dir}")
    print(f"  Mode:    {'Source file mapping' if add_processed_func else 'Using processed_func column'}")
    print("=" * 60)
    
    if project == "Real_Vul":
        csv_path = input_dir / "Real_Vul_data.csv"
    else:
        csv_path = input_dir / f"{project}_dataset.csv"
    
    if add_processed_func:
        # 기존 로직: source code 파일에서 매핑
        if project == "Real_Vul":
            source_dir = input_dir / "all_source_code"
            file_ext = ".c"
        else:
            source_dir = input_dir / "source_code"
            tar_path = input_dir / f"{project}_source_code.tar.gz"
            file_ext = ""
            if not extract_source_code(tar_path, source_dir):
                return 1
        
        if not source_dir.exists():
            print(f"[ERROR] Source directory not found: {source_dir}")
            return 1
        
        result = convert_to_json(csv_path, source_dir, output_dir, file_extension=file_ext)
    else:
        # 새 로직: CSV의 processed_func 컬럼 사용
        result = convert_to_json_from_csv(csv_path, output_dir)
    
    if not result:
        return 1
    
    print_summary(project, result, input_dir, output_dir)
    return 0


def run_in_container(absolute_path: str, output_path: Optional[str], add_processed_func: bool = False) -> int:
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
    
    cmd = ["docker", "exec", CONTAINER_NAME, "python3", CONTAINER_SCRIPT_PATH, "--path", absolute_path]
    if output_path:
        cmd.extend(["--output", output_path])
    if add_processed_func:
        cmd.append("--add-processed-func")
    
    exec_result = subprocess.run(cmd, text=True)
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


def parse_absolute_path(absolute_path: str) -> Optional[Tuple[str, str]]:
    """
    Parse absolute path to extract project name.
    
    Expected format: /.../{realvul|realvul_test}/{project}
    
    Returns:
        tuple of (dataset_type, project) or None if invalid
    """
    path = Path(absolute_path)
    parts = path.parts
    
    # 최소 경로 깊이 확인
    if len(parts) < 2:
        return None
    
    project = parts[-1]  # 마지막: project name
    dataset_type = parts[-2]  # 그 앞: realvul or realvul_test
    
    # 유효성 검사 (vpbench도 지원)
    if dataset_type not in ["realvul", "realvul_test", "vpbench"]:
        return None
    
    if project not in AVAILABLE_PROJECTS:
        return None
    
    return (dataset_type, project)


def main():
    parser = argparse.ArgumentParser(
        description="Prepare RealVul dataset for PDBERT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul/jasper
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul/jasper --output /PDBERT/output/jasper
    python prepare_dataset.py --path /PDBERT/data/datasets/extrinsic/vul_detect/realvul_test/Real_Vul --output /PDBERT/output/real_vul
    
Available Projects:
    Chrome, FFmpeg, ImageMagick, jasper, krb5, linux, openssl, php-src, qemu, tcpdump, Real_Vul
        """
    )
    parser.add_argument(
        "--path", 
        required=True,
        help="Absolute path to input dataset directory (e.g., /PDBERT/data/.../realvul/jasper)"
    )
    parser.add_argument(
        "--output", "-o",
        required=False,
        default=None,
        help="Absolute path to output directory (default: same as input path)"
    )
    parser.add_argument(
        "--add-processed-func",
        action="store_true",
        default=False,
        help="Map code from source files (all_source_code/source_code). Without this flag, uses processed_func column from CSV."
    )
    
    args = parser.parse_args()
    input_path = args.path
    output_path = args.output
    add_processed_func = args.add_processed_func
    
    # 입력 경로: 절대경로 여부 확인
    if not input_path.startswith('/'):
        print(f"[ERROR] Input path must be absolute (start with '/'): {input_path}")
        print("[INFO] Example: /PDBERT/data/datasets/extrinsic/vul_detect/realvul/jasper")
        return 1
    
    # 출력 경로: 지정된 경우 절대경로 여부 확인
    if output_path and not output_path.startswith('/'):
        print(f"[ERROR] Output path must be absolute (start with '/'): {output_path}")
        print("[INFO] Example: /PDBERT/output/jasper")
        return 1
    
    # 경로에서 dataset_type과 project 추출
    parsed = parse_absolute_path(input_path)
    if parsed is None:
        print(f"[ERROR] Invalid path format: {input_path}")
        print("[INFO] Expected: /.../{realvul|realvul_test}/{project}")
        print(f"[INFO] Available projects: {', '.join(AVAILABLE_PROJECTS)}")
        return 1
    
    dataset_type, project = parsed
    
    # 출력 경로 기본값: 입력 경로와 동일
    if output_path is None:
        output_path = input_path
    
    if is_in_container():
        # Running inside container - execute directly
        return process_project(project, Path(input_path), Path(output_path), add_processed_func)
    else:
        # Running on host - copy and execute in container
        print("=" * 60)
        print("RealVul Dataset Preparation for PDBERT (Host)")
        print(f"  Input:        {input_path}")
        print(f"  Output:       {output_path}")
        print(f"  Dataset Type: {dataset_type}")
        print(f"  Project:      {project}")
        print("=" * 60)
        
        if not check_container_running():
            print(f"[ERROR] Container '{CONTAINER_NAME}' is not running.")
            print("[INFO] Start with: docker compose up -d pdbert")
            return 1
        
        return run_in_container(input_path, output_path, add_processed_func)


if __name__ == "__main__":
    sys.exit(main())
