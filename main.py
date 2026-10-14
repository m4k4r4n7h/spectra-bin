import sys
import argparse
from spectra import BinaryReverseEngine


def main():
    parser = argparse.ArgumentParser(description="Spectra-Bin Multi-Language Reverse Engineering Engine")
    parser.add_argument("binary", help="Path to the target binary file to analyze")
    args = parser.parse_args()

    try:
        engine = BinaryReverseEngine(args.binary)
        engine.render_report()
    except FileNotFoundError:
        print(f"Error: Target file '{args.binary}' not found.", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"Error: Permission denied reading '{args.binary}'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
