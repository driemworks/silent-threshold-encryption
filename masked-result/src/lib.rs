// src/lib.rs
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, Expr};

/// Procedural macro for side-channel resistant error handling
/// 
/// In debug mode, errors pass through normally for debugging.
/// In release mode, all errors are mapped to the specified constant-time error.
/// 
/// # Usage
/// ```ignore
/// #[masked(Error::EncryptionError)]
/// fn sensitive_function() -> Result<T, Error> {
///     // Function body - errors automatically masked in release builds
///     fallible_operation()?;
///     Ok(result)
/// }
/// ```
#[proc_macro_attribute]
pub fn masked(args: TokenStream, input: TokenStream) -> TokenStream {
    let fallback_error = parse_macro_input!(args as Expr);
    let input_fn = parse_macro_input!(input as ItemFn);
    
    generate_masked_function(fallback_error, input_fn)
}

fn generate_masked_function(fallback_error: Expr, input_fn: ItemFn) -> TokenStream {
    let fn_vis = &input_fn.vis;
    let fn_name = &input_fn.sig.ident;
    let fn_generics = &input_fn.sig.generics;
    let fn_inputs = &input_fn.sig.inputs;
    let fn_output = &input_fn.sig.output;
    let fn_block = &input_fn.block;
    let fn_attrs = &input_fn.attrs;
    
    let expanded = quote! {
        #(#fn_attrs)*
        #fn_vis fn #fn_name #fn_generics(#fn_inputs) #fn_output {
            #[cfg(debug_assertions)]
            {
                // Development mode: pass through original errors
                #fn_block
            }
            
            #[cfg(not(debug_assertions))]
            {
                // Production mode: mask all errors for constant-time behavior
                let result: Result<_, _> = (|| #fn_block)();
                result.map_err(|_| #fallback_error)
            }
        }
    };
    
    TokenStream::from(expanded)
}

/// Function-like macro for masking specific expressions
/// 
/// # Usage  
/// ```ignore
/// masked_call!(risky_operation(), Error::EncryptionError)?;
/// ```
#[proc_macro]
pub fn masked_call(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as MaskedCallInput);
    
    let expr = input.expr;
    let fallback_error = input.fallback_error;
    
    let expanded = quote! {
        {
            #[cfg(debug_assertions)]
            {
                #expr
            }
            
            #[cfg(not(debug_assertions))]
            {
                (#expr).map_err(|_| #fallback_error)
            }
        }
    };
    
    TokenStream::from(expanded)
}

// Custom parsing for masked_call! macro
struct MaskedCallInput {
    expr: Expr,
    fallback_error: Expr,
}

impl syn::parse::Parse for MaskedCallInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let expr = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        let fallback_error = input.parse()?;
        Ok(MaskedCallInput { expr, fallback_error })
    }
}
