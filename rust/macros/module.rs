// SPDX-License-Identifier: GPL-2.0

use crate::helpers::*;
use proc_macro::{token_stream, Delimiter, Literal, TokenStream, TokenTree};
use std::fmt::Write;

fn expect_string_array(it: &mut token_stream::IntoIter) -> Vec<String> {
    let group = expect_group(it);
    assert_eq!(group.delimiter(), Delimiter::Bracket);
    let mut values = Vec::new();
    let mut it = group.stream().into_iter();

    while let Some(val) = try_string(&mut it) {
        assert!(val.is_ascii(), "Expected ASCII string");
        values.push(val);
        match it.next() {
            Some(TokenTree::Punct(punct)) => assert_eq!(punct.as_char(), ','),
            None => break,
            _ => panic!("Expected ',' or end of array"),
        }
    }
    values
}

struct ModInfoBuilder<'a> {
    module: &'a str,
    counter: usize,
    buffer: String,
    param_buffer: String,
}

impl<'a> ModInfoBuilder<'a> {
    fn new(module: &'a str) -> Self {
        ModInfoBuilder {
            module,
            counter: 0,
            buffer: String::new(),
            param_buffer: String::new(),
        }
    }

    fn emit_base(&mut self, field: &str, content: &str, builtin: bool, param: bool) {
        let string = if builtin {
            // Built-in modules prefix their modinfo strings by `module.`.
            format!(
                "{module}.{field}={content}\0",
                module = self.module,
                field = field,
                content = content
            )
        } else {
            // Loadable modules' modinfo strings go as-is.
            format!("{field}={content}\0")
        };

        let buffer = if param {
            &mut self.param_buffer
        } else {
            &mut self.buffer
        };

        write!(
            buffer,
            "
                {cfg}
                #[doc(hidden)]
                #[cfg_attr(not(target_os = \"macos\"), link_section = \".modinfo\")]
                #[used(compiler)]
                pub static __{module}_{counter}: [u8; {length}] = *{string};
            ",
            cfg = if builtin {
                "#[cfg(not(MODULE))]"
            } else {
                "#[cfg(MODULE)]"
            },
            module = self.module.to_uppercase(),
            counter = self.counter,
            length = string.len(),
            string = Literal::byte_string(string.as_bytes()),
        )
        .unwrap();

        self.counter += 1;
    }

    fn emit_only_builtin(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, true, param)
    }

    fn emit_only_loadable(&mut self, field: &str, content: &str, param: bool) {
        self.emit_base(field, content, false, param)
    }

    fn emit(&mut self, field: &str, content: &str) {
        self.emit_internal(field, content, false);
    }

    fn emit_internal(&mut self, field: &str, content: &str, param: bool) {
        self.emit_only_builtin(field, content, param);
        self.emit_only_loadable(field, content, param);
    }

    fn emit_param(&mut self, field: &str, param: &str, content: &str) {
        let content = format!("{param}:{content}", param = param, content = content);
        self.emit_internal(field, &content, true);
    }

    fn emit_params(&mut self, info: &ModuleInfo) {
        let Some(params) = &info.params else {
            return;
        };

        for param in params {
            let permissions = parse_permissions(&param.permissions);
            let ops = param_ops_path(&param.ptype, permissions);
            let writable = permissions & 0o222 != 0;
            let (access_type, access_initializer) = match (param.ptype.as_str(), writable) {
                ("bool", true) => (
                    "::kernel::module_param::WritableBoolParamAccess".to_string(),
                    format!(
                        "::kernel::module_param::WritableBoolParamAccess::new({})",
                        param.default
                    ),
                ),
                ("u32", true) => (
                    "::kernel::module_param::WritableU32ParamAccess".to_string(),
                    writable_u32_initializer(param),
                ),
                _ => {
                    assert!(
                        param.validator.is_none(),
                        "A validator is supported only for writable u32 parameters"
                    );
                    (
                        format!("::kernel::module_param::ModuleParamAccess<{}>", param.ptype),
                        format!(
                            "::kernel::module_param::ModuleParamAccess::<{}>::new({})",
                            param.ptype, param.default
                        ),
                    )
                }
            };

            // Note: The spelling of these fields is dictated by the user space
            // tool `modinfo`.
            if param.modinfo_type.as_deref() != Some("") {
                self.emit_param(
                    "parmtype",
                    &param.name,
                    param.modinfo_type.as_deref().unwrap_or(&param.ptype),
                );
            }
            if let Some(description) = &param.description {
                self.emit_param("parm", &param.name, description);
            }

            write!(
                self.param_buffer,
                "
                pub(crate) static {param_name}: {access_type} =
                    {access_initializer};

                const _: () = {{
                    #[link_section = \"__param\"]
                    #[used]
                    static __{module_name}_{param_name}_struct:
                        ::kernel::module_param::KernelParam =
                        ::kernel::module_param::KernelParam::new(
                            ::kernel::bindings::kernel_param {{
                                name: if ::core::cfg!(MODULE) {{
                                    ::kernel::c_str!(\"{param_name}\").to_bytes_with_nul()
                                }} else {{
                                    ::kernel::c_str!(\"{module_name}.{param_name}\")
                                        .to_bytes_with_nul()
                                }}.as_ptr(),
                                // SAFETY: `__this_module` is constructed by the kernel at load
                                // time and will not be freed until the module is unloaded.
                                #[cfg(MODULE)]
                                mod_: unsafe {{
                                    core::ptr::from_ref(&::kernel::bindings::__this_module)
                                        .cast_mut()
                                }},
                                #[cfg(not(MODULE))]
                                mod_: ::core::ptr::null_mut(),
                                ops: core::ptr::from_ref(&{ops}),
                                perm: {param_permissions},
                                level: -1,
                                flags: 0,
                                __bindgen_anon_1: ::kernel::bindings::kernel_param__bindgen_ty_1 {{
                                    arg: {param_name}.as_void_ptr()
                                }},
                            }}
                        );
                }};
                ",
                module_name = info.name,
                param_permissions = format!("0o{:o}", permissions),
                param_name = param.name,
                access_type = access_type,
                access_initializer = access_initializer,
                ops = ops,
            )
            .unwrap();
        }
    }
}

fn param_ops_path(param_type: &str, permissions: u16) -> &'static str {
    if permissions & 0o222 != 0 {
        return match param_type {
            "bool" => "::kernel::module_param::PARAM_OPS_BOOL_WRITABLE",
            "u32" => "::kernel::module_param::PARAM_OPS_U32_WRITABLE",
            t => panic!("Writable parameter type {t} is not supported"),
        };
    }

    if permissions != 0 {
        return match param_type {
            "i32" => "::kernel::module_param::PARAM_OPS_I32_READABLE",
            "u32" => "::kernel::module_param::PARAM_OPS_U32_READABLE",
            "bool" => "::kernel::module_param::PARAM_OPS_BOOL_READABLE",
            t => panic!("Readable parameter type {t} is not supported"),
        };
    }

    match param_type {
        "i8" => "::kernel::module_param::PARAM_OPS_I8",
        "u8" => "::kernel::module_param::PARAM_OPS_U8",
        "i16" => "::kernel::module_param::PARAM_OPS_I16",
        "u16" => "::kernel::module_param::PARAM_OPS_U16",
        "i32" => "::kernel::module_param::PARAM_OPS_I32",
        "u32" => "::kernel::module_param::PARAM_OPS_U32",
        "i64" => "::kernel::module_param::PARAM_OPS_I64",
        "u64" => "::kernel::module_param::PARAM_OPS_U64",
        "isize" => "::kernel::module_param::PARAM_OPS_ISIZE",
        "usize" => "::kernel::module_param::PARAM_OPS_USIZE",
        "bool" => "::kernel::module_param::PARAM_OPS_BOOL",
        t => panic!("Unsupported parameter type {}", t),
    }
}

fn parse_u32_literal(raw: &str) -> u32 {
    let compact = raw.replace('_', "");
    let (radix, digits) = if let Some(digits) = compact.strip_prefix("0x") {
        (16, digits)
    } else if let Some(digits) = compact.strip_prefix("0o") {
        (8, digits)
    } else if let Some(digits) = compact.strip_prefix("0b") {
        (2, digits)
    } else {
        (10, compact.as_str())
    };
    u32::from_str_radix(digits, radix).expect("Invalid u32 module parameter value")
}

fn writable_u32_initializer(param: &Parameter) -> String {
    match param.validator.as_deref() {
        None => format!(
            "::kernel::module_param::WritableU32ParamAccess::new({}, 0, u32::MAX)",
            param.default
        ),
        Some("possible_queues") => format!(
            "::kernel::module_param::WritableU32ParamAccess::possible_queues({})",
            param.default
        ),
        Some(range) => {
            let (minimum, maximum) = range
                .split_once("..=")
                .expect("u32 validator must be `minimum..=maximum` or `possible_queues`");
            let minimum_value = parse_u32_literal(minimum);
            let maximum_value = parse_u32_literal(maximum);
            let default_value = parse_u32_literal(&param.default);
            assert!(
                minimum_value <= maximum_value,
                "Invalid u32 validator range"
            );
            assert!(
                (minimum_value..=maximum_value).contains(&default_value),
                "Default u32 parameter value is outside its validator range"
            );
            format!(
                "::kernel::module_param::WritableU32ParamAccess::new({}, {}, {})",
                param.default, minimum, maximum
            )
        }
    }
}

fn expect_param_default(param_it: &mut token_stream::IntoIter, param_type: &str) -> String {
    assert_eq!(expect_ident(param_it), "default");
    assert_eq!(expect_punct(param_it), ':');
    let value = if param_type == "bool" {
        let default = expect_ident(param_it);
        assert!(
            default == "true" || default == "false",
            "Expected Boolean default param value"
        );
        default
    } else {
        let sign = try_sign(param_it);
        let default = try_literal(param_it).expect("Expected default param value");
        let mut value = sign.map(String::from).unwrap_or_default();
        value.push_str(&default);
        value
    };
    assert_eq!(expect_punct(param_it), ',');
    value
}

fn expect_param_permissions(param_it: &mut token_stream::IntoIter) -> String {
    let mut probe = param_it.clone();
    let Some(TokenTree::Ident(ident)) = probe.next() else {
        return "0".to_string();
    };
    if ident.to_string() != "permissions" {
        return "0".to_string();
    }

    assert_eq!(expect_ident(param_it), "permissions");
    assert_eq!(expect_punct(param_it), ':');
    let permissions = try_literal(param_it).expect("Expected module parameter permissions");
    assert_eq!(expect_punct(param_it), ',');
    parse_permissions(&permissions);
    permissions
}

fn parse_permissions(raw: &str) -> u16 {
    let compact = raw.replace('_', "");
    let (radix, digits) = if let Some(digits) = compact.strip_prefix("0o") {
        (8, digits)
    } else if let Some(digits) = compact.strip_prefix("0x") {
        (16, digits)
    } else if let Some(digits) = compact.strip_prefix("0b") {
        (2, digits)
    } else {
        (10, compact.as_str())
    };
    let permissions =
        u16::from_str_radix(digits, radix).expect("Invalid module parameter permissions");
    assert!(
        permissions <= 0o777,
        "Module parameter permissions must fit Unix mode bits"
    );
    permissions
}

#[derive(Debug, Default)]
struct ModuleInfo {
    type_: String,
    license: String,
    name: String,
    authors: Option<Vec<String>>,
    description: Option<String>,
    version: Option<String>,
    alias: Option<Vec<String>>,
    firmware: Option<Vec<String>>,
    imports_ns: Option<Vec<String>>,
    params: Option<Vec<Parameter>>,
}

#[derive(Debug)]
struct Parameter {
    name: String,
    ptype: String,
    default: String,
    permissions: String,
    validator: Option<String>,
    modinfo_type: Option<String>,
    description: Option<String>,
}

fn expect_params(it: &mut token_stream::IntoIter) -> Vec<Parameter> {
    let params = expect_group(it);
    assert_eq!(params.delimiter(), Delimiter::Brace);
    let mut it = params.stream().into_iter();
    let mut parsed = Vec::new();

    loop {
        let param_name = match it.next() {
            Some(TokenTree::Ident(ident)) => ident.to_string(),
            Some(_) => panic!("Expected Ident or end"),
            None => break,
        };

        assert_eq!(expect_punct(&mut it), ':');
        let param_type = expect_ident(&mut it);
        let group = expect_group(&mut it);
        assert_eq!(group.delimiter(), Delimiter::Brace);
        assert_eq!(expect_punct(&mut it), ',');

        let mut param_it = group.stream().into_iter();
        let param_default = expect_param_default(&mut param_it, &param_type);
        let param_permissions = expect_param_permissions(&mut param_it);
        let param_validator = {
            let mut probe = param_it.clone();
            match probe.next() {
                Some(TokenTree::Ident(ident)) if ident.to_string() == "validator" => {
                    Some(expect_string_field(&mut param_it, "validator"))
                }
                _ => None,
            }
        };
        let param_modinfo_type = {
            let mut probe = param_it.clone();
            match probe.next() {
                Some(TokenTree::Ident(ident)) if ident.to_string() == "modinfo_type" => {
                    Some(expect_string_field(&mut param_it, "modinfo_type"))
                }
                _ => None,
            }
        };
        let param_description = {
            let mut probe = param_it.clone();
            match probe.next() {
                Some(TokenTree::Ident(ident)) if ident.to_string() == "description" => {
                    Some(expect_string_field(&mut param_it, "description"))
                }
                _ => None,
            }
        };
        expect_end(&mut param_it);

        parsed.push(Parameter {
            name: param_name,
            ptype: param_type,
            default: param_default,
            permissions: param_permissions,
            validator: param_validator,
            modinfo_type: param_modinfo_type,
            description: param_description,
        })
    }

    parsed
}

impl ModuleInfo {
    fn parse(it: &mut token_stream::IntoIter) -> Self {
        let mut info = ModuleInfo::default();

        const EXPECTED_KEYS: &[&str] = &[
            "type",
            "name",
            "authors",
            "description",
            "license",
            "version",
            "alias",
            "firmware",
            "imports_ns",
            "params",
        ];
        const REQUIRED_KEYS: &[&str] = &["type", "name", "license"];
        let mut seen_keys = Vec::new();

        loop {
            let key = match it.next() {
                Some(TokenTree::Ident(ident)) => ident.to_string(),
                Some(_) => panic!("Expected Ident or end"),
                None => break,
            };

            if seen_keys.contains(&key) {
                panic!("Duplicated key \"{key}\". Keys can only be specified once.");
            }

            assert_eq!(expect_punct(it), ':');

            match key.as_str() {
                "type" => info.type_ = expect_ident(it),
                "name" => info.name = expect_string_ascii(it),
                "authors" => info.authors = Some(expect_string_array(it)),
                "description" => info.description = Some(expect_string(it)),
                "license" => info.license = expect_string_ascii(it),
                "version" => info.version = Some(expect_string_ascii(it)),
                "alias" => info.alias = Some(expect_string_array(it)),
                "firmware" => info.firmware = Some(expect_string_array(it)),
                "imports_ns" => info.imports_ns = Some(expect_string_array(it)),
                "params" => info.params = Some(expect_params(it)),
                _ => panic!("Unknown key \"{key}\". Valid keys are: {EXPECTED_KEYS:?}."),
            }

            assert_eq!(expect_punct(it), ',');

            seen_keys.push(key);
        }

        expect_end(it);

        for key in REQUIRED_KEYS {
            if !seen_keys.iter().any(|e| e == key) {
                panic!("Missing required key \"{key}\".");
            }
        }

        let mut ordered_keys: Vec<&str> = Vec::new();
        for key in EXPECTED_KEYS {
            if seen_keys.iter().any(|e| e == key) {
                ordered_keys.push(key);
            }
        }

        if seen_keys != ordered_keys {
            panic!("Keys are not ordered as expected. Order them like: {ordered_keys:?}.");
        }

        info
    }
}

pub(crate) fn module(ts: TokenStream) -> TokenStream {
    let mut it = ts.into_iter();

    let info = ModuleInfo::parse(&mut it);

    // Rust does not allow hyphens in identifiers, use underscore instead.
    let ident = info.name.replace('-', "_");
    let mut modinfo = ModInfoBuilder::new(ident.as_ref());
    if let Some(authors) = &info.authors {
        for author in authors {
            modinfo.emit("author", author);
        }
    }
    if let Some(description) = &info.description {
        modinfo.emit("description", description);
    }
    modinfo.emit("license", &info.license);
    if let Some(version) = &info.version {
        modinfo.emit("version", version);
    }
    if let Some(aliases) = &info.alias {
        for alias in aliases {
            modinfo.emit("alias", alias);
        }
    }
    if let Some(firmware) = &info.firmware {
        for fw in firmware {
            modinfo.emit("firmware", fw);
        }
    }
    if let Some(imports) = &info.imports_ns {
        for ns in imports {
            modinfo.emit("import_ns", ns);
        }
    }

    // Built-in modules also export the `file` modinfo string.
    let file =
        std::env::var("RUST_MODFILE").expect("Unable to fetch RUST_MODFILE environmental variable");
    modinfo.emit_only_builtin("file", &file, false);

    modinfo.emit_params(&info);

    format!(
        "
            /// The module name.
            ///
            /// Used by the printing macros, e.g. [`info!`].
            const __LOG_PREFIX: &[u8] = b\"{name}\\0\";

            // SAFETY: `__this_module` is constructed by the kernel at load time and will not be
            // freed until the module is unloaded.
            #[cfg(MODULE)]
            static THIS_MODULE: ::kernel::ThisModule = unsafe {{
                extern \"C\" {{
                    static __this_module: ::kernel::types::Opaque<::kernel::bindings::module>;
                }}

                ::kernel::ThisModule::from_ptr(__this_module.get())
            }};
            #[cfg(not(MODULE))]
            static THIS_MODULE: ::kernel::ThisModule = unsafe {{
                ::kernel::ThisModule::from_ptr(::core::ptr::null_mut())
            }};

            /// The `LocalModule` type is the type of the module created by `module!`,
            /// `module_pci_driver!`, `module_platform_driver!`, etc.
            type LocalModule = {type_};

            impl ::kernel::ModuleMetadata for {type_} {{
                const NAME: &'static ::kernel::str::CStr = c\"{name}\";
            }}

            // Double nested modules, since then nobody can access the public items inside.
            mod __module_init {{
                mod __module_init {{
                    use super::super::{type_};
                    use pin_init::PinInit;

                    /// The \"Rust loadable module\" mark.
                    //
                    // This may be best done another way later on, e.g. as a new modinfo
                    // key or a new section. For the moment, keep it simple.
                    #[cfg(MODULE)]
                    #[doc(hidden)]
                    #[used(compiler)]
                    static __IS_RUST_MODULE: () = ();

                    static mut __MOD: ::core::mem::MaybeUninit<{type_}> =
                        ::core::mem::MaybeUninit::uninit();

                    // Loadable modules need to export the `{{init,cleanup}}_module` identifiers.
                    /// # Safety
                    ///
                    /// This function must not be called after module initialization, because it may be
                    /// freed after that completes.
                    #[cfg(MODULE)]
                    #[doc(hidden)]
                    #[no_mangle]
                    #[link_section = \".init.text\"]
                    pub unsafe extern \"C\" fn init_module() -> ::kernel::ffi::c_int {{
                        // SAFETY: This function is inaccessible to the outside due to the double
                        // module wrapping it. It is called exactly once by the C side via its
                        // unique name.
                        unsafe {{ __init() }}
                    }}

                    #[cfg(MODULE)]
                    #[doc(hidden)]
                    #[used(compiler)]
                    #[link_section = \".init.data\"]
                    static __UNIQUE_ID___addressable_init_module: unsafe extern \"C\" fn() -> i32 = init_module;

                    #[cfg(MODULE)]
                    #[doc(hidden)]
                    #[no_mangle]
                    #[link_section = \".exit.text\"]
                    pub extern \"C\" fn cleanup_module() {{
                        // SAFETY:
                        // - This function is inaccessible to the outside due to the double
                        //   module wrapping it. It is called exactly once by the C side via its
                        //   unique name,
                        // - furthermore it is only called after `init_module` has returned `0`
                        //   (which delegates to `__init`).
                        unsafe {{ __exit() }}
                    }}

                    #[cfg(MODULE)]
                    #[doc(hidden)]
                    #[used(compiler)]
                    #[link_section = \".exit.data\"]
                    static __UNIQUE_ID___addressable_cleanup_module: extern \"C\" fn() = cleanup_module;

                    // Built-in modules are initialized through an initcall pointer
                    // and the identifiers need to be unique.
                    #[cfg(not(MODULE))]
                    #[cfg(not(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS))]
                    #[doc(hidden)]
                    #[link_section = \"{initcall_section}\"]
                    #[used(compiler)]
                    pub static __{ident}_initcall: extern \"C\" fn() ->
                        ::kernel::ffi::c_int = __{ident}_init;

                    #[cfg(not(MODULE))]
                    #[cfg(CONFIG_HAVE_ARCH_PREL32_RELOCATIONS)]
                    ::core::arch::global_asm!(
                        r#\".section \"{initcall_section}\", \"a\"
                        __{ident}_initcall:
                            .long   __{ident}_init - .
                            .previous
                        \"#
                    );

                    #[cfg(not(MODULE))]
                    #[doc(hidden)]
                    #[no_mangle]
                    pub extern \"C\" fn __{ident}_init() -> ::kernel::ffi::c_int {{
                        // SAFETY: This function is inaccessible to the outside due to the double
                        // module wrapping it. It is called exactly once by the C side via its
                        // placement above in the initcall section.
                        unsafe {{ __init() }}
                    }}

                    #[cfg(not(MODULE))]
                    #[doc(hidden)]
                    #[no_mangle]
                    pub extern \"C\" fn __{ident}_exit() {{
                        // SAFETY:
                        // - This function is inaccessible to the outside due to the double
                        //   module wrapping it. It is called exactly once by the C side via its
                        //   unique name,
                        // - furthermore it is only called after `__{ident}_init` has
                        //   returned `0` (which delegates to `__init`).
                        unsafe {{ __exit() }}
                    }}

                    /// # Safety
                    ///
                    /// This function must only be called once.
                    unsafe fn __init() -> ::kernel::ffi::c_int {{
                        let initer =
                            <{type_} as ::kernel::InPlaceModule>::init(&super::super::THIS_MODULE);
                        // SAFETY: No data race, since `__MOD` can only be accessed by this module
                        // and there only `__init` and `__exit` access it. These functions are only
                        // called once and `__exit` cannot be called before or during `__init`.
                        match unsafe {{ initer.__pinned_init(__MOD.as_mut_ptr()) }} {{
                            Ok(m) => 0,
                            Err(e) => e.to_errno(),
                        }}
                    }}

                    /// # Safety
                    ///
                    /// This function must
                    /// - only be called once,
                    /// - be called after `__init` has been called and returned `0`.
                    unsafe fn __exit() {{
                        // SAFETY: No data race, since `__MOD` can only be accessed by this module
                        // and there only `__init` and `__exit` access it. These functions are only
                        // called once and `__init` was already called.
                        unsafe {{
                            // Invokes `drop()` on `__MOD`, which should be used for cleanup.
                            __MOD.assume_init_drop();
                        }}
                    }}
                    {modinfo}
                }}
            }}
            mod module_parameters {{
                {params}
            }}
        ",
        type_ = info.type_,
        name = info.name,
        ident = ident,
        modinfo = modinfo.buffer,
        params = modinfo.param_buffer,
        initcall_section = ".initcall6.init"
    )
    .parse()
    .expect("Error parsing formatted string into token stream.")
}
