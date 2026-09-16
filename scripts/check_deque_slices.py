import ast
import os

def check_slices():
    server_path = os.path.join("src", "arkshield", "api", "server.py")
    with open(server_path, "r", encoding="utf-8") as f:
        source = f.read()

    tree = ast.parse(source, filename="server.py")
    
    deque_vars = set()
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Name) and isinstance(node.value, ast.Call):
                    if getattr(node.value.func, "id", None) == "deque":
                        deque_vars.add(t.id)
        elif isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.value and isinstance(node.value, ast.Call):
                if getattr(node.value.func, "id", None) == "deque":
                    deque_vars.add(node.target.id)

    class SliceVisitor(ast.NodeVisitor):
        def __init__(self):
            self.issues = []
        def visit_Subscript(self, node):
            if isinstance(node.slice, ast.Slice):
                var_name = None
                if isinstance(node.value, ast.Name):
                    var_name = node.value.id
                if var_name in deque_vars:
                    self.issues.append((node.lineno, var_name, ast.unparse(node)))
            self.generic_visit(node)

    v = SliceVisitor()
    v.visit(tree)

    print(f"Remaining deque slice issues: {len(v.issues)}")
    for lineno, var, expr in v.issues:
        print(f"Line {lineno:5d}: {var} -> {expr}")

if __name__ == "__main__":
    check_slices()
