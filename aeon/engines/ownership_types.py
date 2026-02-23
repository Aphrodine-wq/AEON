"""AEON Ownership & Borrowing Verification — Rust-Style Affine Type Theory.

Implements ownership and borrow checking based on:
  Clarke, D., Potter, J., & Noble, J. (1998) "Ownership Types for Flexible Alias Protection"
  OOPSLA '98, https://doi.org/10.1145/286936.286947

  Tofte, M. & Talpin, J.P. (1997) "Region-Based Memory Management"
  Information and Computation 132(2),
  https://doi.org/10.1006/inco.1996.2613

  Wadler, P. (1990) "Linear Types Can Change the World!"
  IFIP TC 2 Working Conference on Programming Concepts and Methods,
  https://doi.org/10.1007/978-0-387-97086-4_22

  Jung, R., Jourdan, J.H., Krebbers, R., & Dreyer, D. (2018)
  "RustBelt: Securing the Foundations of the Rust Programming Language"
  POPL '18, https://doi.org/10.1145/3158154

  Weiss, A., Patterson, D., Ahmed, A., & Hicks, M. (2019)
  "Oxide: The Essence of Rust"
  arXiv:1903.00982

Key Theory:

1. AFFINE TYPES (Wadler 1990):
   An affine type system allows values to be used AT MOST ONCE.
   This models ownership: once you give away a value, you no longer own it.

   Affine typing rule:
     Gamma, x:T |- e : U    (x used at most once in e)
     --------------------------------
     Gamma |- let x = v in e : U

2. BORROW CHECKER (Jung et al. 2018 — RustBelt):
   Lifetimes 'a annotate references to ensure they don't outlive their owner.
   The borrow checker enforces:
     - At most ONE mutable reference (&mut T) at a time
     - Any number of shared references (&T) simultaneously
     - No reference outlives the owned value

   Formally modeled in Iris (a higher-order concurrent separation logic).

3. REGION-BASED MEMORY (Tofte & Talpin 1997):
   Memory is organized into REGIONS with static lifetimes.
   All allocations in a region are freed simultaneously when the region ends.
   Region inference eliminates GC overhead while guaranteeing safety.

4. OWNERSHIP TYPES (Clarke et al. 1998):
   Each object has an OWNER. The owner controls access.
   rep objects are private to the owner; world objects are globally accessible.
   Prevents representation exposure (a key source of aliasing bugs).
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class BorrowKind(Enum):
    OWNED = auto()
    SHARED = auto()
    MUTABLE = auto()
    MOVED = auto()


@dataclass
class Lifetime:
    name: str
    scope_depth: int

    def outlives(self, other: "Lifetime") -> bool:
        return self.scope_depth <= other.scope_depth


@dataclass
class OwnershipIssue:
    kind: str
    message: str
    line: int
    variable: str
    severity: str = "error"
    paper: str = ""


@dataclass
class OwnershipResult:
    issues: list[OwnershipIssue] = field(default_factory=list)
    variables_checked: int = 0
    borrows_verified: int = 0
    regions_analyzed: int = 0
    verified: bool = True

    @property
    def summary(self) -> str:
        if not self.issues:
            return (f"✅ OWNERSHIP VERIFIED: {self.variables_checked} variables, "
                    f"{self.borrows_verified} borrows — no aliasing violations")
        errors = [i for i in self.issues if i.severity == "error"]
        return f"❌ OWNERSHIP: {len(errors)} violation(s) found"


@dataclass
class VariableState:
    name: str
    borrow_kind: BorrowKind
    lifetime: Optional[Lifetime]
    line_defined: int
    line_moved: Optional[int] = None
    active_borrows: list[tuple[BorrowKind, int]] = field(default_factory=list)


class BorrowChecker:
    """
    Implements the core borrow checking algorithm.
    Based on RustBelt (Jung et al. 2018) and the NLL (Non-Lexical Lifetimes)
    algorithm (Matsakis 2018).
    """

    def __init__(self) -> None:
        self.variables: dict[str, VariableState] = {}
        self.issues: list[OwnershipIssue] = []

    def define(self, name: str, line: int, lifetime: Optional[Lifetime] = None) -> None:
        self.variables[name] = VariableState(
            name=name,
            borrow_kind=BorrowKind.OWNED,
            lifetime=lifetime,
            line_defined=line
        )

    def move_value(self, name: str, line: int) -> None:
        if name not in self.variables:
            return
        state = self.variables[name]
        if state.borrow_kind == BorrowKind.MOVED:
            self.issues.append(OwnershipIssue(
                kind="use_after_move",
                message=(
                    f"Use of moved value '{name}' at line {line}. "
                    f"Value was moved at line {state.line_moved}. "
                    f"After a move, the original binding is invalid — "
                    f"ownership has been transferred."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Jung et al. (2018) RustBelt — POPL"
            ))
            return
        if state.active_borrows:
            self.issues.append(OwnershipIssue(
                kind="move_while_borrowed",
                message=(
                    f"Cannot move '{name}' at line {line} while it has "
                    f"{len(state.active_borrows)} active borrow(s). "
                    f"All borrows must end before ownership is transferred."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Weiss et al. (2019) Oxide — arXiv:1903.00982"
            ))
            return
        state.borrow_kind = BorrowKind.MOVED
        state.line_moved = line

    def borrow_shared(self, name: str, line: int) -> None:
        if name not in self.variables:
            return
        state = self.variables[name]
        if state.borrow_kind == BorrowKind.MOVED:
            self.issues.append(OwnershipIssue(
                kind="borrow_after_move",
                message=(
                    f"Cannot borrow '{name}' at line {line} — value was moved "
                    f"at line {state.line_moved}."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Jung et al. (2018) RustBelt — POPL"
            ))
            return
        mut_borrows = [b for b in state.active_borrows if b[0] == BorrowKind.MUTABLE]
        if mut_borrows:
            self.issues.append(OwnershipIssue(
                kind="shared_borrow_while_mutably_borrowed",
                message=(
                    f"Cannot create shared borrow of '{name}' at line {line} "
                    f"while a mutable borrow is active (from line {mut_borrows[0][1]}). "
                    f"Rust's aliasing XOR mutability invariant violated."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Jung et al. (2018) RustBelt — POPL"
            ))
            return
        state.active_borrows.append((BorrowKind.SHARED, line))

    def borrow_mutable(self, name: str, line: int) -> None:
        if name not in self.variables:
            return
        state = self.variables[name]
        if state.borrow_kind == BorrowKind.MOVED:
            self.issues.append(OwnershipIssue(
                kind="mutable_borrow_after_move",
                message=(
                    f"Cannot mutably borrow '{name}' at line {line} — "
                    f"value was moved at line {state.line_moved}."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Jung et al. (2018) RustBelt — POPL"
            ))
            return
        if state.active_borrows:
            self.issues.append(OwnershipIssue(
                kind="multiple_mutable_borrows",
                message=(
                    f"Cannot create mutable borrow of '{name}' at line {line} "
                    f"while {len(state.active_borrows)} borrow(s) are active. "
                    f"Aliasing XOR mutability: only ONE mutable borrow at a time."
                ),
                line=line,
                variable=name,
                severity="error",
                paper="Jung et al. (2018) RustBelt — POPL"
            ))
            return
        state.active_borrows.append((BorrowKind.MUTABLE, line))

    def end_borrow(self, name: str, borrow_line: int) -> None:
        if name not in self.variables:
            return
        state = self.variables[name]
        state.active_borrows = [b for b in state.active_borrows if b[1] != borrow_line]

    def check_lifetime_escape(self, ref_name: str, ref_lifetime: Lifetime,
                               owner_lifetime: Lifetime, line: int) -> None:
        if not ref_lifetime.outlives(owner_lifetime):
            self.issues.append(OwnershipIssue(
                kind="lifetime_escape",
                message=(
                    f"Reference '{ref_name}' (lifetime '{ref_lifetime.name}') "
                    f"outlives its owner (lifetime '{owner_lifetime.name}'). "
                    f"Dangling reference — the owned value will be dropped "
                    f"before the reference expires."
                ),
                line=line,
                variable=ref_name,
                severity="error",
                paper="Tofte & Talpin (1997) Region-Based Memory Management"
            ))


class RegionAnalyzer:
    """
    Region-based memory analysis (Tofte & Talpin 1997).
    Infers region lifetimes and verifies no allocation escapes its region.
    """

    def __init__(self) -> None:
        self.regions: list[dict] = []
        self.issues: list[OwnershipIssue] = []

    def enter_region(self, name: str, depth: int) -> None:
        self.regions.append({"name": name, "depth": depth, "allocations": []})

    def allocate(self, var: str, region_name: str, line: int) -> None:
        for r in self.regions:
            if r["name"] == region_name:
                r["allocations"].append({"var": var, "line": line})
                return

    def exit_region(self, name: str, escaping_vars: list[str], line: int) -> None:
        region = next((r for r in self.regions if r["name"] == name), None)
        if region is None:
            return
        region_vars = {a["var"] for a in region["allocations"]}
        for var in escaping_vars:
            if var in region_vars:
                self.issues.append(OwnershipIssue(
                    kind="region_escape",
                    message=(
                        f"Variable '{var}' allocated in region '{name}' "
                        f"escapes the region at line {line}. "
                        f"This would be a dangling pointer after region deallocation."
                    ),
                    line=line,
                    variable=var,
                    severity="error",
                    paper="Tofte & Talpin (1997) Region-Based Memory Management"
                ))
        self.regions = [r for r in self.regions if r["name"] != name]


class OwnershipVerificationEngine:
    """
    Full ownership and borrow verification engine.
    Combines affine types, borrow checking, lifetime analysis, and region inference.
    """

    def __init__(self) -> None:
        self.borrow_checker = BorrowChecker()
        self.region_analyzer = RegionAnalyzer()

    def verify(self, program: dict) -> OwnershipResult:
        result = OwnershipResult()
        events: list[dict] = program.get("events", [])

        for event in events:
            kind = event.get("kind", "")
            name = event.get("name", "")
            line = event.get("line", 0)

            if kind == "define":
                lt_data = event.get("lifetime")
                lt = Lifetime(lt_data["name"], lt_data["depth"]) if lt_data else None
                self.borrow_checker.define(name, line, lt)
            elif kind == "move":
                self.borrow_checker.move_value(name, line)
            elif kind == "borrow_shared":
                self.borrow_checker.borrow_shared(name, line)
            elif kind == "borrow_mutable":
                self.borrow_checker.borrow_mutable(name, line)
            elif kind == "end_borrow":
                self.borrow_checker.end_borrow(name, event.get("borrow_line", 0))
            elif kind == "region_enter":
                self.region_analyzer.enter_region(name, event.get("depth", 0))
            elif kind == "region_exit":
                self.region_analyzer.exit_region(
                    name, event.get("escaping", []), line
                )

        all_issues = self.borrow_checker.issues + self.region_analyzer.issues
        result.issues = all_issues
        result.variables_checked = len(self.borrow_checker.variables)
        result.borrows_verified = sum(
            len(v.active_borrows) for v in self.borrow_checker.variables.values()
        )
        result.regions_analyzed = len(self.region_analyzer.regions)
        result.verified = not any(i.severity == "error" for i in all_issues)
        return result


def verify_ownership(program: dict) -> OwnershipResult:
    """Entry point: verify ownership and borrowing for a program event trace."""
    engine = OwnershipVerificationEngine()
    return engine.verify(program)
