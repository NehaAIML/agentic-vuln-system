from utils.llm_client import query_ollama

def self_repair_loop(cve_details, initial_patch, test_traceback, max_attempts=3):
    current_patch = initial_patch
    
    for attempt in range(1, max_attempts + 1):
        print(f"[ATTEMPT {attempt}] Testing patch in sandbox...")
        
        # Run sandbox (your existing code)
        test_passed, error_output = run_sandbox_test(current_patch)
        
        if test_passed:
            print(f"[SUCCESS] Patch verified on attempt {attempt}")
            return current_patch
        
        print(f"[FAILED] Test failed. Reflecting on error...")
        
        # Generate refined patch using Ollama
        reflection_prompt = f"""
        Original CVE: {cve_details}
        Failed Patch:
        {current_patch}
        
        Test Error:
        {error_output}
        
        Analyze the error and provide a corrected unified diff patch.
        """
        
        current_patch = query_ollama(reflection_prompt)
        
        if current_patch is None:
            print("[ERROR] LLM failed to generate response")
            return None
    
    print(f"[REJECTED] Max attempts ({max_attempts}) reached. Patch not verified.")
    return None

def run_sandbox_test(patch):
    """
    Stub for testing the agentic loop.
    Fails if the bad code is still there, passes if the LLM fixed it.
    """
    if "initial bad patch" in patch:
        return False, "Test Failed: The initial bad patch is still here. Please fix the code."
    return True, ""
