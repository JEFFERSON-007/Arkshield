import os
base_dir = r"c:\Users\mariy\OneDrive\Documents\extra tasks i do when i am bored\system scanner\sys scanner"

for root, dirs, files in os.walk(base_dir):
    dirs[:] = [d for d in dirs if d not in ('.git', '.venv', '__pycache__')]
    for f in files:
        if f.endswith(('.py', '.md')):
            p = os.path.join(root, f)
            try:
                with open(p, 'r', encoding='utf-8') as file:
                    c = file.read()
                if "ARKSHIELD" in c:
                    c = c.replace("ARKSHIELD", "ARKSHIELD")
                    with open(p, 'w', encoding='utf-8') as file:
                        file.write(c)
                    print(f"Updated {p}")
            except Exception as e:
                pass
