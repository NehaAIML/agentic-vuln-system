from agent.self_repair import self_repair_loop

def test_self_repair_success_on_first_try():
    mock_patch_gen = lambda ctx: "mock diff"
    mock_test_runner = lambda: {"success": True, "stdout": "ok", "stderr": ""}
    
    success = self_repair_loop(mock_patch_gen, mock_test_runner, "initial context", max_attempts=3)
    assert success is True

def test_self_repair_exhaustion():
    mock_patch_gen = lambda ctx: "mock diff"
    mock_test_runner = lambda: {"success": False, "stdout": "", "stderr": "error"}
    
    success = self_repair_loop(mock_patch_gen, mock_test_runner, "initial context", max_attempts=2)
    assert success is False
