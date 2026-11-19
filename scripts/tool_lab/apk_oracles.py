"""Provider-independent facts for an inert, self-authored APK round trip.

Every function here reads authored text, the built ZIP container, or the
decoded tree directly. Nothing trusts an MCP success flag and no APK is
executed, installed, or attached to a device.
"""
from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path
import xml.etree.ElementTree as ET

ORACLE_LITERAL = "APK_ORACLE_2b9c"
RESOURCE_LITERAL = "APK_ROUNDTRIP_7d41"
PACKAGE_NAME = "lab.demo"
CLASS_NAME = "lab.demo.MainActivity"
CLASS_DESCRIPTOR = "Llab/demo/MainActivity;"
METHOD_SIGNATURE = ".method public static labValue()Ljava/lang/String;"

MANIFEST_TEXT = (
    '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
    'package="lab.demo"><application android:label="@string/lab_label">'
    '<activity android:name=".MainActivity" /></application></manifest>\n'
)
SMALI_TEXT = (
    ".class public Llab/demo/MainActivity;\n"
    ".super Ljava/lang/Object;\n"
    ".method public static labValue()Ljava/lang/String;\n"
    "    .registers 1\n"
    '    const-string v0, "APK_ORACLE_2b9c"\n'
    "    return-object v0\n"
    ".end method\n"
)
STRINGS_TEXT = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<resources>\n"
    '    <string name="lab_label">Owned lab</string>\n'
    '    <string name="lab_greeting">APK_ROUNDTRIP_7d41</string>\n'
    "</resources>\n"
)
COLORS_TEXT = (
    '<?xml version="1.0" encoding="utf-8"?>\n'
    "<resources>\n"
    '    <color name="lab_accent">#112233</color>\n'
    "</resources>\n"
)
APKTOOL_YML_TEMPLATE = (
    "version: {apktool_version}\n"
    "apkFileName: LabFixture.apk\n"
    "sdkInfo:\n"
    "  minSdkVersion: '21'\n"
    "  targetSdkVersion: '21'\n"
    "usesFramework:\n"
    "  ids:\n"
    "  - 1\n"
    "  tag: null\n"
)

REQUIRED_APK_ENTRIES = ("AndroidManifest.xml", "classes.dex", "resources.arsc")
AXML_MAGIC = "03000800"
DEX_MAGIC = "6465780a30333500"
ARSC_MAGIC = "02000c00"

_LOCALS = re.compile(r"^\.locals\s+")


def authored_files(apktool_version: str = "3.0.3") -> dict[str, str]:
    """Return the complete authored fixture as relative path -> exact text."""
    return {
        "AndroidManifest.xml": MANIFEST_TEXT,
        "apktool.yml": APKTOOL_YML_TEMPLATE.format(apktool_version=apktool_version),
        "smali/lab/demo/MainActivity.smali": SMALI_TEXT,
        "res/values/strings.xml": STRINGS_TEXT,
        "res/values/colors.xml": COLORS_TEXT,
    }


def write_authored_project(root: Path, apktool_version: str = "3.0.3") -> dict[str, str]:
    """Write the fixture with exact bytes (no Windows newline translation)."""
    files = authored_files(apktool_version)
    for relative, text in files.items():
        path = Path(root) / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return files


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest_file(path: Path) -> str:
    return digest_bytes(Path(path).read_bytes())


def snapshot_tree(root: Path) -> dict[str, str]:
    """Names and bytes: a refused mutation cannot add an unseen file."""
    root = Path(root)
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        result[relative] = digest_file(path) if path.is_file() else "directory"
    return result


def canonical_smali(text: str) -> list[str]:
    """Normalize only what baksmali legitimately rewrites.

    Baksmali emits ``.locals`` where the authored source said ``.registers``,
    adds section comments, and changes blank lines. Opcodes, registers, and
    literals must remain byte-for-byte identical after this normalization.
    """
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(_LOCALS.sub(".registers ", line))
    return lines


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def manifest_tree(text: str):
    """Order-sensitive element tree with sorted attributes, namespace-insensitive tags."""
    def node(element):
        return (
            _local_name(element.tag),
            tuple(sorted(element.attrib.items())),
            tuple(node(child) for child in element),
        )
    return node(ET.fromstring(text))


def manifest_facts(text: str) -> dict:
    root = ET.fromstring(text)

    def attr(element, name):
        for key, value in element.attrib.items():
            if _local_name(key) == name:
                return value
        return None

    application = next(
        (element for element in root.iter() if _local_name(element.tag) == "application"),
        None,
    )
    return {
        "package": attr(root, "package"),
        "application_label": attr(application, "label") if application is not None else None,
        "activities": [
            attr(element, "name")
            for element in root.iter()
            if _local_name(element.tag) == "activity"
        ],
    }


def resource_values(text: str, tag: str) -> dict[str, str]:
    root = ET.fromstring(text)
    return {
        element.attrib.get("name"): (element.text or "")
        for element in root.iter()
        if _local_name(element.tag) == tag
    }


def public_resources(text: str) -> list[dict[str, str]]:
    root = ET.fromstring(text)
    return [
        {
            "type": element.attrib.get("type"),
            "name": element.attrib.get("name"),
            "id": element.attrib.get("id"),
        }
        for element in root.iter()
        if _local_name(element.tag) == "public"
    ]


def apktool_yml_facts(text: str) -> dict:
    """Line-scoped YAML facts; avoids a PyYAML dependency in the lab client."""
    facts = {
        "version": None,
        "apk_file_name": None,
        "min_sdk": None,
        "target_sdk": None,
        "framework_ids": [],
    }
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line == "sdkInfo:":
            section = "sdk"
            continue
        if line == "usesFramework:":
            section = "framework"
            continue
        if line.startswith("version:"):
            facts["version"] = line.split(":", 1)[1].strip()
        elif line.startswith("apkFileName:"):
            facts["apk_file_name"] = line.split(":", 1)[1].strip()
        elif section == "sdk" and line.startswith("minSdkVersion:"):
            facts["min_sdk"] = line.split(":", 1)[1].strip()
        elif section == "sdk" and line.startswith("targetSdkVersion:"):
            facts["target_sdk"] = line.split(":", 1)[1].strip()
        elif section == "framework" and line.startswith("- "):
            facts["framework_ids"].append(line[2:].strip())
    return facts


def apk_facts(path: Path) -> dict:
    path = Path(path)
    data = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        entries = {name: archive.read(name) for name in names}
        zip_test = archive.testzip()
    return {
        "path": str(path),
        "size": len(data),
        "sha256": digest_bytes(data),
        "zip_test": zip_test,
        "names": names,
        "entries": {
            name: {
                "size": len(payload),
                "sha256": digest_bytes(payload),
                "magic": payload[:4].hex(),
            }
            for name, payload in entries.items()
        },
        "manifest_magic": entries["AndroidManifest.xml"][:4].hex()
        if "AndroidManifest.xml" in entries
        else None,
        "dex_magic": entries["classes.dex"][:8].hex() if "classes.dex" in entries else None,
        "arsc_magic": entries["resources.arsc"][:4].hex()
        if "resources.arsc" in entries
        else None,
        "dex_has_oracle_literal": ORACLE_LITERAL.encode() in entries.get("classes.dex", b""),
        "arsc_has_resource_literal": RESOURCE_LITERAL.encode()
        in entries.get("resources.arsc", b""),
    }


def decoded_facts(root: Path, apk: dict) -> dict:
    root = Path(root)
    tree = snapshot_tree(root)
    files = {name: value for name, value in tree.items() if value != "directory"}

    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    manifest_text = read("AndroidManifest.xml")
    smali_text = read("smali/lab/demo/MainActivity.smali")
    strings_text = read("res/values/strings.xml")
    colors_text = read("res/values/colors.xml")
    public_text = read("res/values/public.xml")
    yml_text = read("apktool.yml")
    original_sha256 = digest_file(root / "original/AndroidManifest.xml")

    public = public_resources(public_text)
    return {
        "file_sha256": files,
        "smali_files": sorted(name for name in files if name.endswith(".smali")),
        "canonical_smali": canonical_smali(smali_text),
        "manifest_tree": manifest_tree(manifest_text),
        "manifest_facts": manifest_facts(manifest_text),
        "strings": resource_values(strings_text, "string"),
        "colors": resource_values(colors_text, "color"),
        "public": public,
        "public_ids_unique": len({entry["id"] for entry in public}) == len(public),
        "public_ids_package_7f": all(
            re.fullmatch(r"0x7f[0-9a-f]{6}", entry["id"] or "") for entry in public
        ),
        "apktool_yml": apktool_yml_facts(yml_text),
        "original_manifest_sha256": original_sha256,
        "original_manifest_matches_apk": original_sha256
        == apk["entries"]["AndroidManifest.xml"]["sha256"],
    }
