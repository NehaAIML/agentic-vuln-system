import time

def self_repair_loop(patch_generator_func, test_runner_func, initial_context: str, max_attempts: int = 3) -> bool:
    """Executes an iterative self-repair loop feeding test errors back to the model."""
    current_context = initial_context
    
    for attempt in range(1, max_attempts + 1):
        print(f"[SelfRepair] Patch generation attempt {attempt} of {max_attempts}...")
        
        # Generate patch variant
        patch = patch_generator_func(current_context)
        
        # Run verification inside sandbox
        test_result = test_runner_func()
        
        if test_result["success"]:
            print(f"[SelfRepair] Success! All tests passed cleanly on attempt {attempt}.")
            return True
        else:
            print(f"[SelfRepair] Test failure encountered. Feeding traceback into reflection prompt...")
            error_msg = test_result["stderr"] or test_result["stdout"]
            current_context = f"{initial_context}\n\nPREVIOUS ATTEMPT FAILED WITH ERROR:\n{error_msg}\nFix the patch logic."
            time.sleep(1)
            
    print("[SelfRepair] Max repair attempts reached. Escalating to human reviewer queue.")
    return False
