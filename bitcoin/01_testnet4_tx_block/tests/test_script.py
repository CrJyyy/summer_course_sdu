from btc_lab.script import classify_script, disassemble_script


def test_standard_script_classification():
    assert classify_script(bytes.fromhex("76a914" + "11" * 20 + "88ac"))["type"] == "p2pkh"
    assert classify_script(bytes.fromhex("a914" + "22" * 20 + "87"))["type"] == "p2sh"
    assert classify_script(bytes.fromhex("0014" + "33" * 20))["type"] == "p2wpkh"
    assert classify_script(bytes.fromhex("0020" + "44" * 32))["type"] == "p2wsh"
    assert classify_script(bytes.fromhex("5120" + "55" * 32))["type"] == "p2tr"
    assert classify_script(bytes.fromhex("6a026869"))["type"] == "op_return"


def test_disassembly_data_push_and_unknown_opcode():
    result = disassemble_script(bytes.fromhex("026869ff"))
    assert result[0]["name"] == "PUSH_2"
    assert result[0]["data"] == "6869"
    assert result[1]["name"] == "OP_UNKNOWN_FF"


def test_disassembly_marks_truncated_push():
    result = disassemble_script(bytes.fromhex("05aabb"))
    assert "truncated" in result[0]["error"]

