"""Regression tests for the ATT&CK mapper.

Guards the CP1 fix: classification runs over the COMMAND only, so a technique keyword that
appears solely in returned output (observation) is never claimed.
"""

from __future__ import annotations

from orchestrator.mitre import classify, navigator_layer, technique_names


def test_id_in_observation_does_not_trigger_t1033():
    # The CP1 bug: `id="favicon"` in returned HTML wrongly tagged T1033 on a plain curl step.
    m = classify('curl -s http://10.13.37.20:3000/', '<link id="favicon" rel="icon">')
    assert "T1033" not in m.techniques


def test_real_id_command_triggers_t1033():
    assert "T1033" in classify("id", "uid=0(root)").techniques
    assert "T1033" in classify("whoami; id", "").techniques
    assert "T1033" in classify("sudo id", "").techniques
    assert "T1033" in classify("cat /etc/passwd", "").techniques


def test_id_substring_in_command_is_not_t1033():
    # Real false positives: `id` inside a grep alternation and inside a URL query param must
    # NOT be read as the `id` command.
    grep_pat = "curl -s http://10.13.37.20/x | grep -oE '\"(username|email|id)\"[^,]*'"
    assert "T1033" not in classify(grep_pat, "").techniques
    assert "T1033" not in classify("curl 'http://10.13.37.20/rest/products?id=1'", "").techniques
    assert "T1033" not in classify("curl http://10.13.37.20/userid/1", "").techniques


def test_nmap_maps_to_t1046_from_command():
    assert "T1046" in classify("nmap -sV -p- 10.13.37.20", "irrelevant output").techniques


def test_sqli_in_command_maps_t1190():
    assert "T1190" in classify("curl 'http://10.13.37.20/?q=1 union select 1'", "").techniques


def test_keyword_only_in_observation_is_ignored():
    # "sqlmap" only in the observation text must not claim T1190.
    m = classify("curl -s http://10.13.37.20/", "hint: run sqlmap for more coverage")
    assert "T1190" not in m.techniques


def test_navigator_layer_covers_mapped_techniques():
    layer = navigator_layer("run-x", {"T1046", "T1190"})
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert ids == {"T1046", "T1190"}
    assert technique_names()["T1046"] == "Network Service Discovery"
