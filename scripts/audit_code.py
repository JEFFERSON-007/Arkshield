import ast
import os
import sys

def audit_all_files():
    root_dir = os.path.join("src", "arkshield")
    py_files = []
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith(".py"):
                py_files.append(os.path.join(root, file))

    print(f"Auditing {len(py_files)} Python files in {root_dir}...")
    errors = 0
    for p in py_files:
        try:
            with open(p, "r", encoding="utf-8") as f:
                content = f.read()
            ast.parse(content, filename=p)
        except Exception as e:
            print(f"SYNTAX ERROR in {p}: {e}")
            errors += 1
    if errors == 0:
        print("All files parsed without syntax errors!")

if __name__ == "__main__":
    audit_all_files()
