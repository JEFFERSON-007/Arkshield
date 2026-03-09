import os

file_path = r"c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner\demo_output.txt"
replacements = {
    "nexus_sentinel": "arkshield",
    "Nexus Sentinel": "Arkshield",
    "NEXUS_SENTINEL": "ARKSHIELD",
    "nexus-sentinel": "arkshield-project",
}
try:
    with open(file_path, 'r', encoding='utf-16') as f:
        content = f.read()

    for old, new in replacements.items():
        content = content.replace(old, new)

    with open(file_path, 'w', encoding='utf-16') as f:
        f.write(content)
    print("Fixed demo_output.txt")
except Exception as e:
    print(f"Failed: {e}")
