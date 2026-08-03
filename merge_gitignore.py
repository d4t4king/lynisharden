#!/usr/bin/env python3

import urllib.request
import argparse

def merge_gitignores(file1: str, file2: str, output_file: str):
    unique_lines = set()

    for file_path in [file1, file2]:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                cleaned = line.strip()
                # Keep track of unique rules, ignore blanks and comments
                if cleaned and not cleaned.startswith('#'):
                    unique_lines.add(cleaned)

    with open(output_file, 'w', encoding='utf-8') as outfile:
        for rule in sorted(unique_lines):
            outfile.write(f"{rule}\n")

def advanced_merge(file1_path: str, file2_path: str, output_path: str =".gitignore"):
    unique_rules = set()
    merged_content = []

    for file_path in [file1_path, file2_path]:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # Add a visual separator head between files
                merged_content.append(f"\n# ============================================================\n")

                for line in file:
                    stripped = line.strip()

                    # Proactively keep comments, section headers, and spacing untouched
                    if not stripped or stripped.startswith('#'):
                        merged_content.append(line)
                        continue

                    # Deduplicate actual rules globally
                    if stripped not in unique_rules:
                        unique_rules.add(stripped)
                        merged_content.append(line)
        except FileNotFoundError:
            print(f"WARNING: {file_path} not found!")
    with open(output_path, 'w', encoding='utf-8') as out_file:
        out_file.writelines(merged_content)
        print(f"\U00002705 Successfully combined templates into {output_path} while preserving headers and comments.")

def compare_with_github(merged_file_path: str =".gitignore"):
    github_url = "https://raw.githubusercontent.com/github/gitignore/main/Global/JetBrains.gitignore"

    # 1. Fetch the list GitHub patterns
    try:
        with urllib.request.urlopen(github_url) as response:
            github_patterns = set(line.decode('utf-8').strip() for line in response if line.strip())
    except Exception as e:
        print(f"ERROR: Failed to fetch GitHub .gitignore patterns: {e}")
        return

    # 2. Extract local patterns
    try:
        with open(merged_file_path, 'r', encoding='utf-8') as merged_file:
            local_patterns = set(line.strip() for line in merged_file if line.strip() and not line.startswith('#'))
    except FileNotFoundError:
        print(f"ERROR: Merged file {merged_file_path} not found.")
        return

    # 3. Analyze variations
    missing_from_local = github_patterns - local_patterns
    extra_in_local = local_patterns - github_patterns

    # 4. Display comparative summary
    print("\n🔬 ANALYSIS VS GITHUB OFFICIAL PYTHON TEMPLATE")
    print("==================================================")
    print(f"\n💡 Missing from your file ({len(missing_from_local)}) items suggested by GitHub:")
    if missing_from_local:
        for rule in sorted(missing_from_local):
            print(f"  [*] {rule}")
    else:
        print(" None!  Your file is identical to or a subset of the GitHub standard.")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser("Merge .gitignore files.")
    parser.add_argument("ignore_files", nargs=2, help="The path(s) to the files to combine.  Only accepts 2 files.")
    parser.add_argument('-o', '--output-file', required=True, help="File to write the combined .gitignore")
    parser.add_argument('--advanced', action='store_true', help="Merge .gitignores preserving comments and headers")
    parser.add_argument('--compare-github', action='store_true', help="Compare the merged .gitignore with GitHub's official Python template")
    return parser.parse_args()

def main():
    arguments = parse_arguments()

    if arguments.advanced:
        advanced_merge(arguments.ignore_files[0], arguments.ignore_files[1], arguments.output_file)
    else:
        merge_gitignores(arguments.ignore_files[0], arguments.ignore_files[1], arguments.output_file)

    if arguments.compare_github:
        compare_with_github(arguments.output_file)

if __name__=='__main__':
    raise SystemExit(main())