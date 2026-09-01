from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(__file__).with_name("core.py.tmpl")
TARGETS = (
    ROOT / "copilot" / "hooks" / "unbound.py",
    ROOT / "cursor" / "unbound.py",
    ROOT / "codex" / "hooks" / "unbound.py",
)
BEGIN = "# BEGIN GENERATED SKILL POLICY CORE"
END = "# END GENERATED SKILL POLICY CORE"


def _source_block():
    return SOURCE.read_text(encoding="utf-8").strip()


def _replace(text, block):
    start = text.index(BEGIN)
    finish = text.index(END, start) + len(END)
    return text[:start] + block + text[finish:]


def write():
    block = _source_block()
    for target in TARGETS:
        text = target.read_text(encoding="utf-8")
        target.write_text(_replace(text, block), encoding="utf-8")


def check():
    block = _source_block()
    stale = []
    for target in TARGETS:
        text = target.read_text(encoding="utf-8")
        if _replace(text, block) != text:
            stale.append(str(target.relative_to(ROOT)))
    return stale


if __name__ == "__main__":
    write()
