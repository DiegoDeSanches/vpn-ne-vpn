"""Structural and safety checks for the canonical OnionRoute product copy."""

from pathlib import Path
import re


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
PRODUCT_ROOT = REPOSITORY_ROOT / "docs" / "product"

REQUIRED_FILES = (
    "README.md",
    "product-requirements.md",
    "onboarding.md",
    "traffic-and-routing.md",
    "privacy-and-policies.md",
    "faq-and-troubleshooting.md",
    "error-copy.md",
)

ERROR_IDS = (
    "tor-bootstrap-failed",
    "gateway-unavailable",
    "selected-country-unavailable",
    "token-expired",
    "directory-expired",
    "kill-switch-active",
    "udp-blocked",
    "quic-blocked",
    "hard-rotation-warning",
    "degraded-anonymity",
    "unsupported-application",
    "captive-portal-detected",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_documents() -> dict[str, str]:
    documents: dict[str, str] = {}
    for relative_path in REQUIRED_FILES:
        path = PRODUCT_ROOT / relative_path
        require(path.is_file(), f"Missing product document: {relative_path}")
        documents[relative_path] = path.read_text(encoding="utf-8")
    return documents


def check_positioning_and_coverage(documents: dict[str, str]) -> None:
    requirements = documents["product-requirements.md"]
    for term in (
        "system-wide Tor client",
        "Tor-based privacy tunnel",
        "private onion gateway",
        "country-selectable Tor egress",
    ):
        require(term in requirements, f"Missing canonical positioning term: {term}")

    for mode in ("Standard", "Enhanced", "Maximum", "Direct Tor"):
        require(f"| {mode} |" in requirements, f"Missing mode definition: {mode}")

    coverage = {
        "onboarding.md": (
            "## Экран 1.",
            "## Экран 7.",
            "UDP и QUIC будут заблокированы",
        ),
        "traffic-and-routing.md": (
            "## Поддерживаемый трафик",
            "## Почему UDP не поддерживается",
            "## Выбор страны выхода",
            "## Автоматическая смена цепочек",
            "## Новая личность / identity reset",
            "## Kill switch",
            "## Split tunneling",
        ),
        "privacy-and-policies.md": (
            "## Краткая модель угроз",
            "## Privacy account",
            "## Privacy gateway",
            "## Конкретная политика логирования",
            "## Политика допустимого использования и abuse",
            "## Transparency policy",
            "## Deletion policy",
        ),
        "faq-and-troubleshooting.md": (
            "## FAQ",
            "## Безопасный порядок диагностики",
            "## Captive portal",
        ),
    }
    for filename, required_fragments in coverage.items():
        for fragment in required_fragments:
            require(fragment in documents[filename], f"Missing {fragment!r} in {filename}")


def check_error_copy(error_copy: str) -> None:
    unsafe_primary_action = re.compile(
        r"kill switch|отключ|direct|split tunneling|исключ", re.IGNORECASE
    )
    for index, error_id in enumerate(ERROR_IDS):
        heading = f"## {error_id}"
        start = error_copy.find(heading)
        require(start >= 0, f"Missing error copy block: {error_id}")

        next_start = (
            error_copy.find(f"## {ERROR_IDS[index + 1]}", start)
            if index + 1 < len(ERROR_IDS)
            else error_copy.find("## Accessibility", start)
        )
        require(next_start > start, f"Cannot determine error copy block end: {error_id}")
        block = error_copy[start:next_start]

        require("**Заголовок:**" in block, f"Missing title for error: {error_id}")
        require("**Primary action:**" in block, f"Missing primary action for error: {error_id}")
        primary_match = re.search(r"\*\*Primary action:\*\*[^\r\n]*", block)
        require(primary_match is not None, f"Cannot parse primary action for error: {error_id}")
        require(
            unsafe_primary_action.search(primary_match.group(0)) is None,
            f"Unsafe primary action for error: {error_id}",
        )

    require("Remote rejection text" in error_copy, "Token rejection needs a coarse remote variant")
    require(
        re.search(r"не\s+переключилось", error_copy) is not None,
        "Mode degradation must prohibit silent downgrade",
    )


def check_local_links() -> None:
    link_pattern = re.compile(r"\[[^\]]+\]\(([^)]+\.md(?:#[^)]+)?)\)")
    for markdown_file in PRODUCT_ROOT.glob("*.md"):
        body = markdown_file.read_text(encoding="utf-8")
        for match in link_pattern.finditer(body):
            target = match.group(1).split("#", maxsplit=1)[0]
            if re.match(r"^[a-z]+://", target):
                continue
            resolved_target = markdown_file.parent / target
            require(
                resolved_target.is_file(),
                f"Broken local link in {markdown_file.name}: {target}",
            )


def main() -> None:
    documents = load_documents()
    check_positioning_and_coverage(documents)
    check_error_copy(documents["error-copy.md"])
    check_local_links()
    print(
        "Product documentation validation passed: "
        f"{len(REQUIRED_FILES)} documents, {len(ERROR_IDS)} error states."
    )


if __name__ == "__main__":
    main()
