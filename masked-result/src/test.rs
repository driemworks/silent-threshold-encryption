use masked_result::{masked, masked_call, mask_error, Zeroizing};

#[derive(Debug, PartialEq)]
enum TestError {
    SpecificError,
    GenericError,
}

#[derive(Debug, PartialEq)]
struct TestResult {
    value: i32,
}

// Test the #[masked] attribute macro
#[masked(TestError::GenericError)]
fn test_masked_function(should_fail: bool) -> Result<TestResult, TestError> {
    if should_fail {
        return Err(TestError::SpecificError);
    }
    Ok(TestResult { value: 42 })
}

#[masked(TestError::GenericError)]
fn test_masked_with_zeroizing() -> Result<TestResult, TestError> {
    let mut sensitive_data = Zeroizing::new(vec![1, 2, 3, 4, 5]);
    
    // Simulate some operation that might fail
    if sensitive_data.len() > 3 {
        // In debug: shows SpecificError, in release: shows GenericError
        return Err(TestError::SpecificError);
    }
    
    Ok(TestResult { value: sensitive_data.len() as i32 })
}

fn fallible_operation(should_fail: bool) -> Result<i32, TestError> {
    if should_fail {
        Err(TestError::SpecificError)
    } else {
        Ok(100)
    }
}

#[test]
fn test_masked_function_success() {
    let result = test_masked_function(false);
    assert_eq!(result, Ok(TestResult { value: 42 }));
}

#[test]
fn test_masked_function_failure() {
    let result = test_masked_function(true);
    
    // In debug builds, we get the specific error
    #[cfg(debug_assertions)]
    assert_eq!(result, Err(TestError::SpecificError));
    
    // In release builds, we get the masked generic error
    #[cfg(not(debug_assertions))]
    assert_eq!(result, Err(TestError::GenericError));
}

#[test]
fn test_masked_call_macro() {
    // Test success case
    let result = masked_call!(fallible_operation(false), TestError::GenericError);
    assert_eq!(result, Ok(100));
    
    // Test failure case
    let result = masked_call!(fallible_operation(true), TestError::GenericError);
    
    #[cfg(debug_assertions)]
    assert_eq!(result, Err(TestError::SpecificError));
    
    #[cfg(not(debug_assertions))]
    assert_eq!(result, Err(TestError::GenericError));
}

#[test]
fn test_mask_error_macro() {
    // Test success
    let result = mask_error!(fallible_operation(false), TestError::GenericError);
    assert_eq!(result, Ok(100));
    
    // Test failure
    let result = mask_error!(fallible_operation(true), TestError::GenericError);
    
    #[cfg(debug_assertions)]
    assert_eq!(result, Err(TestError::SpecificError));
    
    #[cfg(not(debug_assertions))]
    assert_eq!(result, Err(TestError::GenericError));
}

#[test]
fn test_zeroizing_integration() {
    let result = test_masked_with_zeroizing();
    
    #[cfg(debug_assertions)]
    assert_eq!(result, Err(TestError::SpecificError));
    
    #[cfg(not(debug_assertions))]
    assert_eq!(result, Err(TestError::GenericError));
}