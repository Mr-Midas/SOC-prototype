"""Arbiterion File Explorer using Python

This script provides a simple file explorer interface for browsing the Arbiterion project
structure and finding useful files quickly. It includes common search patterns and helps
discover what's available in the repository.
"""

import os
from pathlib import Path


def print_project_structure(start_path: Path, indent: int = 0) -> None:
    """Recursively print the project directory structure."""
    indent_str = "  " * indent
    for item in start_path.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            print(f"{indent_str}{item.name}/")
            print_project_structure(item, indent + 1)
        else:
            print(f"{indent_str}{item.name}")


def show_command_examples() -> None:
    """Show common PowerShell commands for navigating the Arbiterion project."""
    print("\n" + "="*60)
    print("POWERLESS COMMANDS TO EXPLORE ARBITERION")
    print("="*60)
    print("\n# Navigate to the project directory")
    print("cd \"%PROJECT_ROOT%\"")
    print()
    print("# List all files and directories")
    print("ls -la")
    print()
    print("# Find Python source files")
    print("Get-ChildItem -Recurse -Filter *.py | Where-Object { $_.FullName -notmatch '\\.venv' }")
    print()
    print("# Search for specific files or classes")
    print("Get-ChildItem -Name \"*.py\" -Recurse | Select-Object Name, Length")
    print()
    print("# Show actual file content")
    print("Get-Content <file_path> -Head 50")
    print()
    print("# Check database schema")
    print("Get-Content .\database\schema.sql")
    print()
    print("# View launcher.py - main startup script")
    print("Get-Content launcher.py")


def find_common_files() -> None:
    """Find common project files and show their locations."""
    print("\n" + "="*60)
    print("KEY FILES IN ARBITERION")
    print("="*60)

    key_files = [
        ("launcher.py", "Main startup script that installs infrastructure and launches the app"),
        ("docker-compose.yml", "Docker configuration for running PostgreSQL, Redis, and the app"),
        ("arbiterion/db/schema.sql", "PostgreSQL database schema"),
        ("arbiterion/main.py", "FastAPI application entry point"),
        ("requirements.txt", "Project dependencies"),
        ("README.md", "Project documentation"),
        ("scripts/smoke_test.py", "End-to-end smoke test script"),
        ("scripts/analyze_cases.py", "Analyze open cases from the database"),
        (".env", "Environment variables configuration"),
        (".env.example", "Environment variables template"),
        ("arbiterion/edr/defender.py", "Windows Defender EDR integration"),
        ("arbiterion/api/auth.py", "Authentication and session management"),
        ("arbiterion/notifications.py", "Notification system for Slack and webhooks"),
    ]

    for file_path, description in key_files:
        full_path = Path.cwd() / file_path
        if full_path.exists():
            size = full_path.stat().st_size
            print(f"\n✓ {file_path}")
            print(f"  Size: {size:,} bytes")
            print(f"  Description: {description}")
        else:
            print(f"\n✗ {file_path} (file not found)")


def show_explorer_options() -> None:
    """Show the explorer options."""
    print("\n" + "="*60)
    print("ARBITERION FILE EXPLORER OPTIONS")
    print("="*60)
    print("\nAvailable commands:")
    print("  1. Show project structure")
    print("  2. Search for specific file pattern")
    print("  3. Show common/project files")
    print("  4. Show command examples")
    print("  5. Exit")


def explorer_main() -> None:
    """Main explorer function."""
    print("Welcome to Arbiterion File Explorer")

    while True:
        show_explorer_options()

        try:
            choice = input("\nSelect an option (1-5): ").strip()

            if choice == "1":
                print("\n" + "="*60)
                print("PROJECT STRUCTURE (first 10 levels deep)")
                print("="*60)
                print_project_structure(Path.cwd(), indent=0)

            elif choice == "2":
                pattern = input("\nEnter search pattern (e.g., *.py, *_test.py): ").strip()
                if pattern:
                    print(f"\nSearching for pattern: {pattern}")
                    print("="*60)
                    for file_path in Path.cwd().rglob(pattern):
                        if ".venv" not in str(file_path) and not file_path.name.startswith('.') and file_path.is_file():
                            print(file_path)

            elif choice == "3":
                find_common_files()

            elif choice == "4":
                show_command_examples()

            elif choice == "5":
                print("\nGoodbye!")
                break

            else:
                print("\nInvalid option. Please select 1-5.")

        except KeyboardInterrupt:
            print("\n\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    print("Initialising Arbiterion File Explorer...")
    explorer_main()
