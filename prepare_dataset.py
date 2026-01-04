#!/usr/bin/env python3
"""
RealVul Dataset Preparation Script for PDBERT
==============================================
This script extracts source code and converts the dataset to JSON format
for vulnerability detection training with PDBERT.

Supports multiple projects from the RealVul dataset.

Usage:
    python prepare_dataset.py <project_name>

Available projects:
    Chrome, FFmpeg, ImageMagick, jasper, krb5, linux, openssl, php-src, qemu, tcpdump
    
Special:
    Real_Vul - Uses Real_Vul_data.csv with all_source_code directory (all projects combined)

Examples:
    python prepare_dataset.py jasper
    python prepare_dataset.py linux
    python prepare_dataset.py Real_Vul  # All projects combined

Output:
    - train.json: Training data (80% of train_val)
    - validate.json: Validation data (20% of train_val)
    - test.json: Test data
"""

import csv
import json
import tarfile
import random
import sys
import argparse
from pathlib import Path


# Available projects in RealVul dataset
AVAILABLE_PROJECTS = [
    "Chrome",
    "FFmpeg",
    "ImageMagick",
    "jasper",
    "krb5",
    "linux",
    "openssl",
    "php-src",
    "qemu",
    "tcpdump",
    "Real_Vul"  # Special: all projects combined
]


def extract_source_code(tar_path: Path, extract_dir: Path) -> bool:
    """Extract source code from archive (supports tar, tar.gz, tar.xz, tar.bz2)."""
    if not tar_path.exists():
        print(f"[ERROR] Archive not found: {tar_path}")
        return False
    
    # Check if already extracted
    if extract_dir.exists() and any(extract_dir.iterdir()):
        print(f"[INFO] Source code already extracted: {extract_dir}")
        return True
    
    print(f"[INFO] Extracting {tar_path}...")
    
    # Try auto-detection of compression format
    try:
        with tarfile.open(tar_path, 'r:*') as tar:
            tar.extractall(path=tar_path.parent)
        print(f"[INFO] Extraction complete.")
        return True
    except tarfile.ReadError as e:
        print(f"[WARN] Auto-detect failed: {e}")
    
    # Try plain tar (no compression)
    try:
        with tarfile.open(tar_path, 'r:') as tar:
            tar.extractall(path=tar_path.parent)
        print(f"[INFO] Extraction complete (plain tar).")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to extract: {e}")
        return False


def convert_to_json(csv_path: Path, source_dir: Path, output_dir: Path, 
                    file_name_key: str = 'file_name', 
                    file_extension: str = '') -> dict:
    """Convert CSV dataset to JSON format for PDBERT.
    
    Args:
        csv_path: Path to CSV file
        source_dir: Path to source code directory
        output_dir: Path to output directory for JSON files
        file_name_key: CSV column name for file name
        file_extension: Extension to append to file name (e.g., '.c')
    """
    if not csv_path.exists():
        print(f"[ERROR] CSV not found: {csv_path}")
        return {}
    
    if not source_dir.exists():
        print(f"[ERROR] Source directory not found: {source_dir}")
        return {}
    
    random.seed(42)
    train_val_data = []
    test_data = []
    stats = {"total": 0, "found": 0, "not_found": 0, "empty": 0, "vul": 0, "non_vul": 0}
    
    print(f"[INFO] Reading CSV: {csv_path}")
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            stats["total"] += 1
            
            # Build source file path
            file_name = row[file_name_key] + file_extension
            source_file = source_dir / file_name
            
            if not source_file.exists():
                stats["not_found"] += 1
                continue
            
            with open(source_file, 'r', errors='ignore') as sf:
                code = sf.read()
            
            # Skip empty source code files (prevents IndexError in code_cleaner)
            if not code or not code.strip():
                stats["empty"] += 1
                continue
            
            stats["found"] += 1
            
            # Determine vulnerability label
            vul_value = 1 if row['vulnerable_line_numbers'].strip() else 0
            if vul_value == 1:
                stats["vul"] += 1
            else:
                stats["non_vul"] += 1
            
            item = {"code": code, "vul": vul_value}
            
            if row['dataset_type'] == "train_val":
                train_val_data.append(item)
            else:
                test_data.append(item)
    
    # Shuffle and split train/validation
    random.shuffle(train_val_data)
    split_idx = int(len(train_val_data) * 0.8)
    
    train_data = train_val_data[:split_idx]
    validate_data = train_val_data[split_idx:]
    
    # Write JSON files
    output_dir.mkdir(parents=True, exist_ok=True)
    
    with open(output_dir / "train.json", 'w', encoding='utf-8') as f:
        json.dump(train_data, f, indent=4)
    print(f"[INFO] Created: {output_dir / 'train.json'}")
    
    with open(output_dir / "validate.json", 'w', encoding='utf-8') as f:
        json.dump(validate_data, f, indent=4)
    print(f"[INFO] Created: {output_dir / 'validate.json'}")
    
    with open(output_dir / "test.json", 'w', encoding='utf-8') as f:
        json.dump(test_data, f, indent=4)
    print(f"[INFO] Created: {output_dir / 'test.json'}")
    
    return {
        "train": len(train_data),
        "validate": len(validate_data),
        "test": len(test_data),
        "stats": stats
    }


def process_single_project(project: str, base_dir: Path) -> int:
    """Process a single project dataset."""
    TAR_PATH = base_dir / f"{project}_source_code.tar.gz"
    CSV_PATH = base_dir / f"{project}_dataset.csv"
    SOURCE_DIR = base_dir / "source_code"  # All projects extract to source_code/
    OUTPUT_DIR = base_dir
    
    print("=" * 60)
    print(f"RealVul Dataset Preparation for PDBERT")
    print(f"Project: {project}")
    print("=" * 60)
    
    # Step 1: Extract source code
    if not extract_source_code(TAR_PATH, SOURCE_DIR):
        return 1
    
    # Step 2: Convert to JSON
    result = convert_to_json(CSV_PATH, SOURCE_DIR, OUTPUT_DIR)
    
    if not result:
        return 1
    
    print_summary(project, result)
    return 0


def process_real_vul_all(base_dir: Path) -> int:
    """Process the complete Real_Vul dataset (all projects combined).
    
    Uses Real_Vul_data.csv and all_source_code directory.
    File names in CSV are like '0', '1', '2' and actual files are '0.c', '1.c', '2.c'
    """
    CSV_PATH = base_dir / "Real_Vul_data.csv"
    SOURCE_DIR = base_dir / "all_source_code"
    OUTPUT_DIR = base_dir
    
    print("=" * 60)
    print(f"RealVul Dataset Preparation for PDBERT")
    print(f"Project: Real_Vul (All Projects Combined)")
    print("=" * 60)
    
    # Check if source directory exists (no extraction needed - already extracted)
    if not SOURCE_DIR.exists():
        print(f"[ERROR] Source directory not found: {SOURCE_DIR}")
        print(f"[INFO] The all_source_code directory should already exist.")
        return 1
    
    print(f"[INFO] Using pre-extracted source directory: {SOURCE_DIR}")
    
    # Convert to JSON (file_name in CSV is like '0', actual file is '0.c')
    result = convert_to_json(
        CSV_PATH, 
        SOURCE_DIR, 
        OUTPUT_DIR,
        file_name_key='file_name',
        file_extension='.c'
    )
    
    if not result:
        return 1
    
    print_summary("Real_Vul", result)
    return 0


def print_summary(project: str, result: dict):
    """Print summary of dataset preparation."""
    print("=" * 60)
    print("Summary")
    print("=" * 60)
    print(f"  Project:            {project}")
    print(f"  Train:              {result['train']} samples")
    print(f"  Validate:           {result['validate']} samples")
    print(f"  Test:               {result['test']} samples")
    print(f"  ---")
    print(f"  Total files in CSV: {result['stats']['total']}")
    print(f"  Files found:        {result['stats']['found']}")
    print(f"  Files not found:    {result['stats']['not_found']}")
    print(f"  Empty files:        {result['stats']['empty']}")
    print(f"  Vulnerable:         {result['stats']['vul']}")
    print(f"  Non-vulnerable:     {result['stats']['non_vul']}")
    print("=" * 60)
    print("Done! You can now run training with:")
    print("  cd /PDBERT/downstream")
    print("  python train_eval_from_config.py -config configs/vul_detect/pdbert_realvul.jsonnet -task_name vul_detect/realvul -average binary")
    print("=" * 60)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Prepare RealVul dataset for PDBERT vulnerability detection training.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Available projects:
  Chrome, FFmpeg, ImageMagick, jasper, krb5, linux, openssl, php-src, qemu, tcpdump

Special:
  Real_Vul - Uses Real_Vul_data.csv with all_source_code directory (all projects combined)

Examples:
  python prepare_dataset.py jasper
  python prepare_dataset.py linux
  python prepare_dataset.py Real_Vul  # All projects combined
        """
    )
    parser.add_argument(
        "project",
        type=str,
        choices=AVAILABLE_PROJECTS,
        help="Project name to prepare dataset for (use 'Real_Vul' for all projects)"
    )
    
    args = parser.parse_args()
    project = args.project
    
    BASE_DIR = Path("/PDBERT/data/datasets/extrinsic/vul_detect/realvul")
    
    # Handle special Real_Vul case
    if project == "Real_Vul":
        return process_real_vul_all(BASE_DIR)
    else:
        return process_single_project(project, BASE_DIR)


if __name__ == "__main__":
    exit(main())
