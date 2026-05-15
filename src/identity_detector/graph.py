import networkx as nx
from typing import List, Set, Tuple

Node = Tuple[str, str]


class PrivilegeGraph:
    """Simple privilege graph modelling users, roles and permissions."""

    def __init__(self):
        self.G = nx.DiGraph()

    def _node(self, kind: str, name: str) -> Node:
        return (kind, name)

    def add_user(self, username: str):
        self.G.add_node(self._node("user", username))

    def add_role(self, role: str):
        self.G.add_node(self._node("role", role))

    def add_permission(self, perm: str):
        self.G.add_node(self._node("perm", perm))

    def assign_role(self, username: str, role: str):
        self.add_user(username)
        self.add_role(role)
        self.G.add_edge(self._node("user", username), self._node("role", role))

    def grant_permission(self, role: str, perm: str):
        self.add_role(role)
        self.add_permission(perm)
        self.G.add_edge(self._node("role", role), self._node("perm", perm))

    def role_inherits(self, child: str, parent: str):
        self.add_role(child)
        self.add_role(parent)
        self.G.add_edge(self._node("role", child), self._node("role", parent))

    def roles_of_user(self, username: str) -> Set[str]:
        node = self._node("user", username)
        if node not in self.G:
            return set()
        return {n[1] for n in self.G.successors(node) if n[0] == "role"}

    def permissions_of_role(self, role: str) -> Set[str]:
        node = self._node("role", role)
        if node not in self.G:
            return set()
        perms = set()
        for succ in nx.descendants(self.G, node) | set(self.G.successors(node)):
            if succ[0] == "perm":
                perms.add(succ[1])
        return perms

    def permissions_of_user(self, username: str) -> Set[str]:
        perms = set()
        for role in self.roles_of_user(username):
            perms |= self.permissions_of_role(role)
        return perms

    def find_escalation_paths(self, username: str, target_perm: str, max_depth: int = 6) -> List[List[str]]:
        """Find simple paths from user's roles to a permission node."""
        paths = []
        start_roles = [self._node("role", r) for r in self.roles_of_user(username)]
        target = self._node("perm", target_perm)
        for r in start_roles:
            if r not in self.G or target not in self.G:
                continue
            try:
                for p in nx.all_simple_paths(self.G, source=r, target=target, cutoff=max_depth):
                    # convert nodes to readable names
                    paths.append([f"{n[0]}:{n[1]}" for n in p])
            except nx.NetworkXNoPath:
                continue
        return paths

    def detect_toxic_combinations(self, username: str, toxic_sets: List[Set[str]]) -> List[Set[str]]:
        roles = self.roles_of_user(username)
        found = []
        for toks in toxic_sets:
            if toks.issubset(roles):
                found.append(toks)
        return found
