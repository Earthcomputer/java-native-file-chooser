use jni::objects::{GlobalRef, JMethodID, JObject, JString};
use jni::signature::JavaType;
use jni::sys::{jint, jlong, jlongArray, jmethodID, jobjectArray, jsize, JNI_ERR, JNI_VERSION_1_8};
use jni::{JNIEnv, JavaVM};
use raw_window_handle::RawWindowHandle;
use std::ffi::c_void;
use std::mem::MaybeUninit;
use std::ops::{Deref, DerefMut};
use std::str::Utf8Error;
use std::{mem, ptr};

#[allow(warnings)]
mod jawt {
    include!(concat!(env!("OUT_DIR"), "/jawt.rs"));
}

struct Ids {
    t_string: JavaType,
    t_string_array: JavaType,
    _c_file_filter: GlobalRef,
    m_file_filter_get_description: jmethodID,
    m_file_filter_get_extensions: jmethodID,
}

static mut IDS: MaybeUninit<Ids> = MaybeUninit::uninit();

const MODE_OPEN_SINGLE: jint = 0;
const MODE_OPEN_MULTIPLE: jint = 1;
const MODE_OPEN_DIR: jint = 2;
const MODE_SAVE_SINGLE: jint = 3;

#[no_mangle]
pub unsafe extern "system" fn JNI_OnLoad(vm: JavaVM, _reserved: *mut c_void) -> jint {
    let ids = match vm.get_env().and_then(make_ids) {
        Ok(ids) => ids,
        Err(_) => return JNI_ERR,
    };

    // Safety: this is initialization, nothing else should be accessing IDS yet
    IDS = MaybeUninit::new(ids);

    JNI_VERSION_1_8
}

fn make_ids(env: JNIEnv) -> jni::errors::Result<Ids> {
    let c_file_filter = env.find_class("net/earthcomputer/nativeFileChooser/FileFilter")?;
    let m_file_filter_get_description = env
        .get_method_id(c_file_filter, "getDescription", "()Ljava/lang/String;")?
        .into_inner();
    let m_file_filter_get_extensions = env
        .get_method_id(c_file_filter, "getExtensions", "()[Ljava/lang/String;")?
        .into_inner();
    let c_file_filter = env.auto_local(c_file_filter);
    Ok(Ids {
        t_string: JavaType::Object("java/lang/String".to_owned()),
        t_string_array: JavaType::Array(Box::new(JavaType::Object("java/lang/String".to_owned()))),
        _c_file_filter: env.new_global_ref(c_file_filter.as_obj())?,
        m_file_filter_get_description,
        m_file_filter_get_extensions,
    })
}

#[no_mangle]
pub unsafe extern "system" fn JNI_OnUnload(_vm: JavaVM, _reserved: *mut c_void) {
    // Safety: JNI_OnLoad will have been called, and JNI_OnUnload won't have yet been called,
    // this is after everything else can ever be called
    IDS.assume_init_drop();
}

#[no_mangle]
pub extern "system" fn Java_net_earthcomputer_nativeFileChooser_NativeFileChooser_getHInstance(
    env: JNIEnv,
    #[cfg(not(target_family = "windows"))] _dll: JString,
    #[cfg(target_family = "windows")] dll: JString,
) -> jlong {
    #[cfg(not(target_family = "windows"))]
    {
        let _ = env.throw_new(
            "java/lang/UnsupportedOperationException",
            "getHInstance can only be called on Windows",
        );
        0
    }
    #[cfg(target_family = "windows")]
    {
        if dll.is_null() {
            unsafe {
                return winapi::um::libloaderapi::GetModuleHandleW(ptr::null()) as jlong;
            }
        }
        let str = match env.get_string(dll) {
            Ok(str) => str,
            Err(err) => {
                let _ = env.throw_new("java/lang/Error", err.to_string());
                return 0;
            }
        };
        let str = match str.to_str() {
            Ok(str) => str,
            Err(err) => {
                let _ = env.throw_new("java/lang/Error", err.to_string());
                return 0;
            }
        };
        let mut chars: Vec<_> = str.chars().map(|char| char as u16).collect();
        chars.push(0);

        unsafe { winapi::um::libloaderapi::GetModuleHandleW(chars.as_ptr()) as jlong }
    }
}

#[no_mangle]
pub unsafe extern "system" fn Java_net_earthcomputer_nativeFileChooser_NativeFileChooser_getNativeWindowHandle(
    env: JNIEnv,
    frame: JObject,
) -> jlongArray {
    get_native_window_handle(env, frame)
}

unsafe fn get_native_window_handle(env1: JNIEnv, frame: JObject) -> jlongArray {
    let env = *mem::transmute::<&JNIEnv, &*mut jawt::JNIEnv>(&env1);
    let mut awt = MaybeUninit::uninit();
    if jawt::JAWT_GetAWT(env, awt.as_mut_ptr()) == 0 {
        let _ = env1.throw_new("java/awt/HeadlessException", "");
        return ptr::null_mut();
    }
    let awt = awt.assume_init();

    let ds = awt.GetDrawingSurface.unwrap_unchecked()(env, frame.into_inner() as jawt::jobject);
    if ds.is_null() {
        let _ = env1.throw_new("java/lang/Error", "Can't get drawing surface");
        return ptr::null_mut();
    }
    let ds = cleanup_on_drop(ds, |ds| awt.FreeDrawingSurface.unwrap_unchecked()(ds));
    let lock = (**ds).Lock.unwrap_unchecked()(*ds);
    if (lock as u32 & jawt::JAWT_LOCK_ERROR) != 0 {
        let _ = env1.throw_new("java/lang/Error", "Can't get drawing surface lock");
        return ptr::null_mut();
    }
    let _lock = cleanup_on_drop(lock, |_| (**ds).Unlock.unwrap_unchecked()(*ds));
    let dsi = (**ds).GetDrawingSurfaceInfo.unwrap_unchecked()(*ds);
    if dsi.is_null() {
        let _ = env1.throw_new("java/lang/Error", "Can't get drawing surface info");
        return ptr::null_mut();
    }
    let dsi = cleanup_on_drop(dsi, |dsi| {
        (**ds).FreeDrawingSurfaceInfo.unwrap_unchecked()(dsi)
    });
    let arr = do_get_native_window_handle(env1, (**dsi).platformInfo);
    let result = match env1.new_long_array(arr.len() as jsize) {
        Ok(result) => result,
        Err(err) => {
            let _ = env1.throw_new("java/lang/Error", err.to_string());
            return ptr::null_mut();
        }
    };
    if let Err(err) = env1.set_long_array_region(result, 0, &arr) {
        let _ = env1.throw_new("java/lang/Error", err.to_string());
        return ptr::null_mut();
    }
    result
}

fn cleanup_on_drop<T>(resource: T, cleanup_fn: impl FnOnce(T)) -> impl DerefMut<Target = T> {
    struct Wrapper<T, F: FnOnce(T)>(MaybeUninit<T>, MaybeUninit<F>);
    impl<T, F: FnOnce(T)> Deref for Wrapper<T, F> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { self.0.assume_init_ref() }
        }
    }
    impl<T, F: FnOnce(T)> DerefMut for Wrapper<T, F> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { self.0.assume_init_mut() }
        }
    }
    impl<T, F: FnOnce(T)> Drop for Wrapper<T, F> {
        fn drop(&mut self) {
            let mut resource = MaybeUninit::uninit();
            mem::swap(&mut self.0, &mut resource);
            let resource = unsafe { resource.assume_init() };
            let mut cleanup_fn = MaybeUninit::uninit();
            mem::swap(&mut self.1, &mut cleanup_fn);
            let cleanup_fn = unsafe { cleanup_fn.assume_init() };
            cleanup_fn(resource);
        }
    }
    Wrapper(MaybeUninit::new(resource), MaybeUninit::new(cleanup_fn))
}

#[cfg(not(any(target_family = "windows", target_os = "macos")))]
unsafe fn do_get_native_window_handle(env: JNIEnv, platform_info: *const c_void) -> [jlong; 3] {
    let platform_info = platform_info as *const jawt::JAWT_X11DrawingSurfaceInfo;
    if platform_info.is_null() {
        let _ = env.throw_new("java/lang/Error", "Can't get X11 platform info");
        return [0, 0, 0];
    }
    [
        (*platform_info).drawable as jlong,
        (*platform_info).display as jlong,
        (*platform_info).visualID as jlong,
    ]
}

#[cfg(target_family = "windows")]
const JAWT_NAME: [u16; 9] = [
    'j' as u16, 'a' as u16, 'w' as u16, 't' as u16, '.' as u16, 'd' as u16, 'l' as u16, 'l' as u16,
    0,
];

#[cfg(target_family = "windows")]
unsafe fn do_get_native_window_handle(env: JNIEnv, platform_info: *const c_void) -> [jlong; 2] {
    let platform_info = platform_info as *const jawt::JAWT_Win32DrawingSurfaceInfo;
    if platform_info.is_null() {
        let _ = env.throw_new("java/lang/Error", "Can't get Win32 platform info");
        return [0, 0];
    }
    let hwnd = (*platform_info).__bindgen_anon_1.hwnd;
    if hwnd.is_null() {
        let _ = env.throw_new("java/lang/IllegalStateException", "Can't get HWND");
        return [0, 0];
    }
    let hinstance = winapi::um::libloaderapi::GetModuleHandleW(JAWT_NAME.as_ptr());
    if hinstance.is_null() {
        let _ = env.throw_new("java/lang/IllegalStateException", "Can't get HINSTANCE");
        return [0, 0];
    }
    [hwnd as jlong, hinstance as jlong]
}

#[cfg(target_os = "macos")]
unsafe fn do_get_native_window_handle(env: JNIEnv, platform_info: *const c_void) -> [jlong; 2] {}

#[no_mangle]
pub unsafe extern "system" fn Java_net_earthcomputer_nativeFileChooser_NativeFileChooser_openDialog(
    env: JNIEnv,
    filters: jobjectArray,
    filename: JString,
    location: JString,
    owner: jlongArray,
    mode: jint,
) -> jobjectArray {
    // Safety: this will be called after JNI_OnLoad and before JNI_OnUnload
    let ids = IDS.assume_init_ref();

    match open_dialog(&env, ids, filters, filename, location, owner, mode) {
        Ok(files) => files,
        Err(err) => {
            match err {
                OpenDialogError::Jni(err) => {
                    let _ = env.throw_new("java/lang/Error", err.to_string());
                }
                OpenDialogError::Utf8(err) => {
                    let _ = env.throw_new("java/lang/IllegalArgumentException", err.to_string());
                }
                OpenDialogError::PathToString => {
                    let _ = env.throw_new(
                        "java/lang/IllegalArgumentException",
                        "Cannot convert path to string",
                    );
                }
                OpenDialogError::NativeDialog(native_dialog::Error::IoFailure(err)) => {
                    let _ = env.throw_new("java/io/IOException", err.to_string());
                }
                OpenDialogError::NativeDialog(err) => {
                    let _ = env.throw_new(
                        "net/earthcomputer/nativeFileChooser/OpenDialogException",
                        err.to_string(),
                    );
                }
            }
            ptr::null_mut()
        }
    }
}

#[derive(Debug)]
enum OpenDialogError {
    Jni(jni::errors::Error),
    Utf8(Utf8Error),
    PathToString,
    NativeDialog(native_dialog::Error),
}

impl From<jni::errors::Error> for OpenDialogError {
    fn from(err: jni::errors::Error) -> Self {
        OpenDialogError::Jni(err)
    }
}

impl From<Utf8Error> for OpenDialogError {
    fn from(err: Utf8Error) -> Self {
        OpenDialogError::Utf8(err)
    }
}

impl From<native_dialog::Error> for OpenDialogError {
    fn from(err: native_dialog::Error) -> Self {
        OpenDialogError::NativeDialog(err)
    }
}

struct FileFilter {
    description: String,
    extensions: Vec<String>,
}

fn open_dialog(
    env: &JNIEnv,
    ids: &Ids,
    filters_arr: jobjectArray,
    filename: JString,
    location: JString,
    owner: jlongArray,
    mode: jint,
) -> Result<jobjectArray, OpenDialogError> {
    let num_filters = env.get_array_length(filters_arr)?;
    let mut filters = Vec::with_capacity(num_filters as usize);
    for i in 0..num_filters {
        let filter = env.get_object_array_element(filters_arr, i)?;
        let description = env.call_method_unchecked(
            filter,
            JMethodID::from(ids.m_file_filter_get_description),
            ids.t_string.clone(),
            &[],
        )?;
        if env.exception_check()? {
            return Ok(ptr::null_mut());
        }
        let extensions = env.call_method_unchecked(
            filter,
            JMethodID::from(ids.m_file_filter_get_extensions),
            ids.t_string_array.clone(),
            &[],
        )?;
        if env.exception_check()? {
            return Ok(ptr::null_mut());
        }
        let description = env
            .get_string(description.l()?.into())?
            .to_str()?
            .to_owned();
        let extensions_arr = extensions.l()?.into_inner() as jobjectArray;
        let num_extensions = env.get_array_length(extensions_arr)?;
        let mut extensions = Vec::with_capacity(num_extensions as usize);
        for j in 0..num_extensions {
            extensions.push(
                env.get_string(env.get_object_array_element(extensions_arr, j)?.into())?
                    .to_str()?
                    .to_owned(),
            );
        }
        filters.push(FileFilter {
            description,
            extensions,
        });
    }
    let extensions_ref: Vec<Vec<_>> = filters
        .iter()
        .map(|filter| filter.extensions.iter().map(|ext| ext.as_str()).collect())
        .collect();

    let mut dialog = native_dialog::FileDialog::new();
    for (filter, extensions) in filters.iter().zip(&extensions_ref) {
        dialog = dialog.add_filter(&filter.description, &extensions);
    }

    let filename = if filename.is_null() {
        None
    } else {
        Some(env.get_string(filename)?.to_str()?.to_owned())
    };
    if let Some(filename) = &filename {
        dialog = dialog.set_filename(filename.as_str());
    }

    let location = if location.is_null() {
        None
    } else {
        Some(env.get_string(location)?.to_str()?.to_owned())
    };
    if let Some(location) = &location {
        dialog = dialog.set_location(location.as_str());
    }

    if !owner.is_null() {
        #[cfg(not(any(target_family = "windows", target_os = "macos")))]
        const EXPECTED_LEN: usize = 3;
        #[cfg(any(target_family = "windows", target_os = "macos"))]
        const EXPECTED_LEN: usize = 2;
        let owner_len = env.get_array_length(owner)?;
        if owner_len as usize != EXPECTED_LEN {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("Expected owner.length to be {EXPECTED_LEN}"),
            )?;
            return Ok(ptr::null_mut());
        }

        let mut owner_arr = [0; EXPECTED_LEN];
        env.get_long_array_region(owner, 0, &mut owner_arr)?;

        #[cfg(not(any(target_family = "windows", target_os = "macos")))]
        let handle = {
            let mut handle = raw_window_handle::XlibHandle::empty();
            handle.window = owner_arr[0] as _;
            handle.display = owner_arr[1] as _;
            handle.visual_id = owner_arr[2] as _;
            RawWindowHandle::Xlib(handle)
        };
        #[cfg(target_family = "windows")]
        let handle = {
            let mut handle = raw_window_handle::Win32Handle::empty();
            handle.hwnd = owner_arr[0] as _;
            handle.hinstance = owner_arr[1] as _;
            RawWindowHandle::Win32(handle)
        };
        #[cfg(target_os = "macos")]
        let handle = {
            let mut handle = raw_window_handle::AppKitHandle::empty();
            handle.ns_window = owner_arr[0] as _;
            handle.ns_view = owner_arr[1] as _;
            RawWindowHandle::AppKit(handle)
        };

        unsafe {
            dialog = dialog.set_owner_handle(handle);
        }
    }

    let results: Vec<_> = match mode {
        MODE_OPEN_SINGLE => dialog.show_open_single_file()?.into_iter().collect(),
        MODE_OPEN_MULTIPLE => dialog.show_open_multiple_file()?,
        MODE_OPEN_DIR => dialog.show_open_single_dir()?.into_iter().collect(),
        MODE_SAVE_SINGLE => dialog.show_save_single_file()?.into_iter().collect(),
        _ => {
            env.throw_new(
                "java/lang/IllegalArgumentException",
                format!("Invalid mode {mode}"),
            )?;
            return Ok(ptr::null_mut());
        }
    };

    let ret = env.new_object_array(results.len() as jsize, "java/lang/String", ptr::null_mut())?;
    for (i, result) in results.into_iter().enumerate() {
        env.set_object_array_element(
            ret,
            i as jsize,
            env.new_string(
                result
                    .into_os_string()
                    .into_string()
                    .map_err(|_| OpenDialogError::PathToString)?,
            )?,
        )?;
    }
    Ok(ret)
}
