import os

base_dir = r"c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner"

# 1. Rename files and directories
renames = {
    r"src\nexus_sentinel": r"src\arkshield",
    r"tests\demo_sentinel.py": r"tests\demo_arkshield.py",
    r"docs\NEXUS_SENTINEL_INDEX.md": r"docs\ARKSHIELD_INDEX.md",
    r"nexus_sentinel.log": r"arkshield.log",
}

for src_rel, dst_rel in renames.items():
    src_path = os.path.join(base_dir, src_rel)
    dst_path = os.path.join(base_dir, dst_rel)
    if os.path.exists(src_path):
        try:
            os.rename(src_path, dst_path)
            print(f"Renamed {src_rel} to {dst_rel}")
        except Exception as e:
            print(f"Failed to rename {src_rel}: {e}")

# 2. Text replacements
replacements = {
    "nexus_sentinel": "arkshield",
    "Nexus Sentinel": "Arkshield",
    "NEXUS_SENTINEL": "ARKSHIELD",
    "nexus-sentinel": "arkshield-project", # Setup.py name or similar
}

for root, dirs, files in os.walk(base_dir):
    # Exclude directories
    dirs[:] = [d for d in dirs if d not in ('.git', '.venv', '__pycache__', 'node_modules')]
    for file in files:
        if file.endswith(('.pyc', '.png', '.jpg', '.ico', '.db', '.sqlite3')):
            continue
        file_path = os.path.join(root, file)
        
        # skip script itself
        if "rename_script.py" in file_path:
            continue
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            new_content = content
            for old, new in replacements.items():
                new_content = new_content.replace(old, new)
                
            if new_content != content:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Updated content in {os.path.relpath(file_path, base_dir)}")
        except Exception as e:
            print(f"Could not process {file_path}: {e}")

print("Done.")
