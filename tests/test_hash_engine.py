"""
tests/test_hash_engine.py
-------------------------
Comprehensive unit tests for backend/hash_engine.py to maximize test coverage.
"""

import struct
import zipfile
import io
import sys
from unittest.mock import patch, MagicMock
import pytest

# Streamlit-i mock edirik ki, daxili asılılıqlar problem yaratmasın
sys.modules["streamlit"] = MagicMock()

from backend.hash_engine import (
    HashAnalysisResult,
    _compute_hashes,
    _normalise_hash,
    _vt_file_lookup,
    _parse_vt_file,
    _extract_pdf_metadata,
    _extract_pdf_text,
    _analyze_content_nlp,
    _extract_office_metadata,
    _extract_pe_metadata,
    analyze_hash
)


# ── 1. HASH UTILITIES TESTS ──────────────────────────────────────────────────

def test_compute_hashes():
    data = b"GhostWire_CTI_Test_Data"
    sha256_h, md5_h, sha1_h = _compute_hashes(data)
    assert len(sha256_h) == 64
    assert len(md5_h) == 32
    assert len(sha1_h) == 40


@pytest.mark.parametrize("hash_str,expected_type", [
    ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
    ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
    ("d41d8cd98f00b204e9800998ecf8427e", "md5"),
    ("invalid_hash_value", "unknown"),
])
def test_normalise_hash(hash_str, expected_type):
    h_val, h_type = _normalise_hash(hash_str)
    if expected_type != "unknown":
        assert h_type == expected_type
        assert h_val == hash_str.lower()
    else:
        assert h_type == "unknown"


# ── 2. VIRUSTOTAL LOOKUP TESTS ───────────────────────────────────────────────

@patch("requests.get")
def test_vt_file_lookup_status_codes(mock_get):
    # Case 200: Success
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": "vt_data"}
    mock_get.return_value = mock_resp
    assert _vt_file_lookup("fake_sha", "fake_key") == {"data": "vt_data"}

    # Case 404: Not Found
    mock_resp.status_code = 404
    assert "not found" in _vt_file_lookup("fake_sha", "fake_key")["error"].lower()

    # Case 500: Server Error
    mock_resp.status_code = 500
    assert "HTTP 500" in _vt_file_lookup("fake_sha", "fake_key")["error"]

    # Case Exception
    mock_get.side_effect = Exception("Timeout")
    assert "Timeout" in _vt_file_lookup("fake_sha", "fake_key")["error"]


def test_parse_vt_file_scenarios():
    # Case: Input has error
    res = HashAnalysisResult()
    _parse_vt_file({"error": "Some VT Error"}, res)
    assert any("Some VT Error" in e for e in res.errors)

    # Case: Malicious threshold >= 20
    res = HashAnalysisResult()
    mock_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 25, "suspicious": 2, "harmless": 40},
                "type_description": "Win2000 Executable",
                "tags": ["macro", "pe"],
                "popular_threat_classification": {"suggested_threat_label": "WannaCry"}
            }
        }
    }
    _parse_vt_file(mock_data, res)
    assert res.vt_malicious == 25
    assert res.score >= 50
    assert "WannaCry" in res.vt_family
    assert any("MALICIOUS 🔴" in f for f in res.flags)
    assert res.has_macros is True

    # Case: Malicious threshold >= 5
    res = HashAnalysisResult()
    mock_data["data"]["attributes"]["last_analysis_stats"]["malicious"] = 8
    _parse_vt_file(mock_data, res)
    assert any("8 malicious detections" in f for f in res.flags)

    # Case: Malicious threshold >= 1
    res = HashAnalysisResult()
    mock_data["data"]["attributes"]["last_analysis_stats"]["malicious"] = 2
    _parse_vt_file(mock_data, res)
    assert any("engine(s) flagged file" in f for f in res.flags)


# ── 3. PDF METADATA & TEXT TESTS ─────────────────────────────────────────────

def test_extract_pdf_metadata_and_indicators():
    res = HashAnalysisResult()
    # İçində Launch, JavaScript və şübhəli müəllif olan saxta PDF baytları
    pdf_bytes = (
        b"%PDF-1.5\n"
        b"/Author (msfvenom_creator)\n"
        b"/Creator (msfvenom)\n"
        b"/Type /Page\n/Type /Page\n"
        b"/JavaScript\n/JS\n/EmbeddedFile\n/Launch\n/OpenAction\n"
    )
    _extract_pdf_metadata(pdf_bytes, res)
    assert res.creator_tool == "msfvenom"
    assert res.page_count == 2
    assert res.has_embedded_objects is True
    assert res.has_auto_open is True
    assert any("potential exploit vector" in f for f in res.flags)
    assert any("executes external commands 🚨" in f for f in res.flags)


def test_extract_pdf_text_fallback_regex():
    # pypdf yüklü olub-olmamasından asılı olmayaraq, Regex fallback rejimini test edirik
    pdf_bytes = b"%PDF-1.4\nBT\n(GhostWire Forensic Alert) Tj\nET\n"
    text = _extract_pdf_text(pdf_bytes)
    assert "GhostWire Forensic Alert" in text


# ── 4. CONTENT NLP & AI OVERRIDES TESTS ──────────────────────────────────────

def test_analyze_content_nlp_heuristics():
    res = HashAnalysisResult()
    phishing_text = (
        "URGENT: Your bank account has been suspended! "
        "Click here immediately to reset your password and confirm credentials. "
        "DHL delivery shipment update required. Overdue invoice payment."
    )
    _analyze_content_nlp(phishing_text, res)
    assert any("Urgency language detected" in f for f in res.flags)
    assert any("Credential harvesting language" in f for f in res.flags)
    assert "CONTENT_CREDENTIAL_HARVEST" in res.iocs


@patch("backend.ai_analyzer.analyze_text")
def test_analyze_content_nlp_ai_overrides(mock_ai_analyze):
    # Ollama AI cavabını mock edirik
    mock_ai_result = MagicMock()
    mock_ai_result.error = None
    mock_ai_result.urgency_detected = True
    mock_ai_result.financial_threat_detected = True
    mock_ai_result.manipulation_detected = True
    mock_ai_result.summary = "Malicious phishing document targeting credentials."
    mock_ai_result.score = 25
    mock_ai_analyze.return_value = mock_ai_result

    res = HashAnalysisResult()
    # Minimal Heuristic pattern keçsin deyə mətni uzun qoyuruq
    _analyze_content_nlp("This is a long sample text to activate Ollama deep analysis processing.", res)
    
    assert any("Ollama" in f for f in res.flags)
    # Həm urgency, həm manipulation, həm financial aktiv olduğu üçün score floor HIGH (60) olmalıdır
    assert res.score >= 60
    assert any("score floor HIGH" in f for f in res.flags)


# ── 5. OFFICE & PE METADATA TESTS ────────────────────────────────────────────

def test_extract_office_metadata_with_macros():
    res = HashAnalysisResult()
    
    # Yaddaşda (In-memory) saxta bir Office ZIP arxivi yaradırıq
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("docProps/core.xml", "<cp:coreProperties xmlns:cp='..'><dc:creator>admin</dc:creator></cp:coreProperties>")
        zf.writestr("docProps/app.xml", "<Application>Microsoft Excel</Application>")
        zf.writestr("word/vbaProject.bin", "AutoOpen Document_Open payload content")
        zf.writestr("word/embeddings/oleObject1.bin", "embedded data")
        
    office_bytes = zip_buffer.getvalue()
    _extract_office_metadata(office_bytes, res)
    
    assert res.author == "admin"
    assert res.has_macros is True
    assert res.has_auto_open is True
    assert res.has_embedded_objects is True
    assert "OFFICE_MACRO" in res.iocs


def test_extract_pe_metadata_packed_and_imports():
    res = HashAnalysisResult()
    
    # Saxta PE Header (MZ + PE signatures + compile timestamp + sections) qururuq
    pe_data = bytearray(b"MZ" + b"\x00" * 58)
    pe_data[0x3C:0x40] = struct.pack("<I", 64) # PE offset = 64
    pe_data.extend(b"PE\x00\x00")
    pe_data.extend(struct.pack("<H", 2))       # Machine
    pe_data.extend(struct.pack("<H", 1))       # Number of Sections = 1
    pe_data.extend(struct.pack("<I", 0))       # Invalid/Zeroed Compile Timestamp
    pe_data.extend(b"\x00" * 10)
    pe_data.extend(struct.pack("<H", 0))       # Size of Optional Header
    pe_data.extend(b"\x00" * 2)                # Characteristics
    
    # Section Table: Section adı və ölçüləri
    pe_data.extend(b".packed\x00")             # Section Name
    pe_data.extend(struct.pack("<I", 100))     # Virtual Size
    pe_data.extend(struct.pack("<I", 1000))    # Virtual Address
    pe_data.extend(struct.pack("<I", 10))      # Size of Raw Data
    pe_data.extend(struct.pack("<I", len(pe_data) + 12)) # Pointer to Raw Data
    pe_data.extend(b"\x00" * 16)
    
    # Section-un daxili datası (Yüksək entropiya verməsi üçün unikal baytlar)
    pe_data.extend(bytes(range(10)))
    # Şübhəli import stringləri əlavə edirik
    pe_data.extend(b"InternetOpenUrlA WriteProcessMemory CreateRemoteThread")
    
    _extract_pe_metadata(bytes(pe_data), res)
    assert any("timestamp stomping" in f for f in res.flags)
    assert "CreateRemoteThread" in res.suspicious_imports
    assert any("Suspicious PE imports" in f for f in res.flags)


# ── 6. MAIN ENGINE ENTRYPOINT TESTS ──────────────────────────────────────────

def test_analyze_hash_string_input():
    # Səhv formatlı hash inputu
    res = analyze_hash("invalid_hash")
    assert any("Unrecognised hash format" in e for e in res.errors)

    # Düzgün hash inputu (VirusTotal API açarı olmadan)
    valid_sha256 = "dae063c6c0ca8e05e4df5e2fb28b4d13ae5f9f60444d3255bfef95601890afd8"
    res = analyze_hash(valid_sha256, vt_api_key=None)
    assert any("VirusTotal API key not configured" in e for e in res.errors)


def test_analyze_hash_zip_bomb_detection():
    # 100 MB-dan böyük (məsələn 110 MB) sıxılmamış ölçü simulyasiya edirik
    # Boşluq simvollarından istifadə edirik ki, sıxılanda cəmi bir neçə kilobayt yer tutsun (yüksək ratio)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        # 110.000.000 baytlıq böyük data əlavə edirik (110 MB)
        zf.writestr("huge_bomb_file.txt", " " * 110_000_000)
        
    bomb_bytes = zip_buffer.getvalue()
    res = analyze_hash(bomb_bytes, filename="alert.zip")
    
    # Həm limit keçiləcək, həm də ratio avtomatik olaraq > 100 olacaq
    assert any("ZIP BOMB" in f for f in res.flags)
    assert any("extraction blocked" in f for f in res.flags)


def test_analyze_hash_legacy_ole2():
    # OLE2 Fayl Formatı üçün Magic Bytes arqumenti
    ole2_bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + b"AutoOpen VBA macro payload"
    res = analyze_hash(ole2_bytes)
    assert res.file_type == "Legacy Office Document (OLE2)"
    assert res.has_macros is True
    assert any("VBA macro signatures found" in f for f in res.flags)


def test_analyze_hash_pdf_and_metadata_author_anomaly():
    pdf_bytes = b"%PDF-1.4\n" + b"/Author (test)\n" + b"BT\n(Urgent password reset required now!)\nET"
    res = analyze_hash(pdf_bytes)
    assert res.file_type == "PDF Document"
    assert any("Generic/suspicious document author" in f for f in res.flags)