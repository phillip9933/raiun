//! Reviewed native Task Scheduler boundary. No script host, remote connection,
//! process termination, application credential persistence, or broad task enumeration.
use super::{OwnedTaskSpec, StartupKind, TaskBinding, TaskStatus, foreign, invalid};
use std::{
    io,
    marker::PhantomData,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    rc::Rc,
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Foundation::VARIANT_BOOL,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoInitializeSecurity, CoUninitialize, EOAC_NONE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
                RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            TaskScheduler::{
                IBootTrigger, IExecAction, ILogonTrigger, IRegisteredTask, ITaskDefinition,
                ITaskFolder, ITaskService, TASK_ACTION_TYPE, TASK_CREATE, TASK_INSTANCES_POLICY,
                TASK_LOGON_INTERACTIVE_TOKEN, TASK_LOGON_PASSWORD, TASK_LOGON_TYPE,
                TASK_RUNLEVEL_TYPE, TASK_TRIGGER_TYPE2, TaskScheduler as TaskSchedulerClass,
            },
            Variant::{VARIANT, VT_BSTR},
        },
    },
    core::{BSTR, Interface},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, HANDLE, LocalFree},
    Security::{
        Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
        GetTokenInformation, LookupAccountNameW, LookupAccountSidW, TOKEN_ELEVATION, TOKEN_QUERY,
        TokenElevation,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
use zeroize::{Zeroize, Zeroizing};

/// All COM objects are released before the apartment guard. Rc's marker keeps
/// the service and its apartment confined to the calling thread.
pub struct TaskScheduler {
    folder: ITaskFolder,
    service: ITaskService,
    sid: String,
    account: String,
    _apartment: Apartment,
}

struct Apartment {
    uninitialize: bool,
    _thread: PhantomData<Rc<()>>,
}

impl Apartment {
    fn enter() -> io::Result<Self> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // An existing STA is usable too. Do not uninitialize an apartment
        // initialized by somebody else when RPC_E_CHANGED_MODE is returned.
        if result.0 == 0x80010106_u32 as i32 {
            return Ok(Self {
                uninitialize: false,
                _thread: PhantomData,
            });
        }
        result
            .ok()
            .map_err(|e| native_error("Initialize local COM", e))?;
        Ok(Self {
            uninitialize: true,
            _thread: PhantomData,
        })
    }
}

impl Drop for Apartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

impl TaskScheduler {
    /// Connect only to the local service as the current process account.
    pub fn connect() -> io::Result<Self> {
        let apartment = Apartment::enter()?;
        initialize_process_security()?;
        let sid = crate::win32::current_user_sid_for_storage()?;
        let account = account_for_sid(&sid)?;
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskSchedulerClass, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| native_error("Create local Task Scheduler", e))?;
        let empty = VARIANT::default();
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }
            .map_err(|e| native_error("Connect local Task Scheduler", e))?;
        let folder = unsafe { service.GetFolder(&BSTR::from("\\")) }
            .map_err(|e| native_error("Open local task folder", e))?;
        Ok(Self {
            folder,
            service,
            sid,
            account,
            _apartment: apartment,
        })
    }

    pub fn current_account(&self) -> &str {
        &self.account
    }
    pub fn current_sid(&self) -> &str {
        &self.sid
    }

    /// A boot registration requires elevation under this same account. This
    /// read-only check should precede the caller's hidden console prompt.
    pub fn boot_is_elevated(&self) -> io::Result<bool> {
        self.verify_account()?;
        let mut raw = std::ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw as RawHandle) };
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if returned as usize != std::mem::size_of::<TOKEN_ELEVATION>() {
            return Err(io::Error::other(
                "Unexpected current-account elevation data",
            ));
        }
        Ok(elevation.TokenIsElevated != 0)
    }

    pub fn inspect_owned(&self, spec: &OwnedTaskSpec) -> io::Result<Option<TaskStatus>> {
        self.verify_account()?;
        self.owned_task(spec)?
            .map(|task| self.status(spec, &task))
            .transpose()
    }

    /// Create only when absent. An already-owned matching task can be enabled
    /// and run; a mode change requires explicit disable/removal first. A failed
    /// immediate Run leaves the registration intact for inspection/recovery.
    pub fn enable(
        &self,
        spec: &OwnedTaskSpec,
        kind: StartupKind,
        password: Option<&str>,
    ) -> io::Result<TaskStatus> {
        self.verify_account()?;
        if kind == StartupKind::Boot && !self.boot_is_elevated()? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Boot-trigger registration requires an elevated terminal under this same Windows account",
            ));
        }
        if kind == StartupKind::Logon && password.is_some() {
            return Err(invalid("Logon startup does not accept a password"));
        }
        if !std::path::Path::new(&spec.executable).is_file()
            || !std::path::Path::new(&spec.working_directory).is_dir()
        {
            return Err(invalid(
                "The startup executable and working directory must exist",
            ));
        }
        let task = if let Some(task) = self.owned_task(spec)? {
            if self.status(spec, &task)?.kind != kind {
                return Err(invalid(
                    "Existing startup mode differs; explicitly disable it before changing mode",
                ));
            }
            self.status(spec, &task)?;
            unsafe { task.SetEnabled(VARIANT_BOOL(-1)) }
                .map_err(|e| native_error("Enable owned startup task", e))?;
            task
        } else {
            let definition = unsafe { self.service.NewTask(0) }
                .map_err(|e| native_error("Prepare startup definition", e))?;
            let xml = BSTR::from(spec.definition_xml(kind, &self.sid)?);
            unsafe { definition.SetXmlText(&xml) }
                .map_err(|e| native_error("Validate startup definition", e))?;
            let user = VARIANT::from(BSTR::from(&self.sid));
            let secret = match kind {
                StartupKind::Boot => {
                    SecretVariant::new(password.filter(|s| !s.is_empty()).ok_or_else(|| {
                        invalid(
                            "Boot startup requires the current account's nonempty Windows password",
                        )
                    })?)?
                }
                StartupKind::Logon => SecretVariant(VARIANT::default()),
            };
            let logon = if kind == StartupKind::Boot {
                TASK_LOGON_PASSWORD
            } else {
                TASK_LOGON_INTERACTIVE_TOKEN
            };
            unsafe { self.folder.RegisterTaskDefinition(&BSTR::from(&spec.task_name), &definition,
                TASK_CREATE.0, &user, &secret.0, logon, &VARIANT::default()) }
                .map_err(|e| native_error("Register owned startup task (verify same-account password, elevation and batch-logon rights)", e))?
        };
        self.status(spec, &task)?;
        unsafe { task.Run(&VARIANT::default()) }.map_err(|e| {
            native_error(
                "Startup registered but immediate launch failed; registration and state preserved",
                e,
            )
        })?;
        self.inspect_owned(spec)?
            .ok_or_else(|| io::Error::other("Startup task disappeared after launch; inspect state"))
    }

    /// Close startup admission only. Caller must request normal agent shutdown
    /// before waiting/removing. No Task.Stop or forced process operation exists.
    pub fn disable_admission(&self, spec: &OwnedTaskSpec) -> io::Result<Option<TaskStatus>> {
        self.verify_account()?;
        let Some(task) = self.owned_task(spec)? else {
            return Ok(None);
        };
        self.status(spec, &task)?;
        unsafe { task.SetEnabled(VARIANT_BOOL(0)) }
            .map_err(|e| native_error("Disable owned startup admission", e))?;
        self.inspect_owned(spec)
    }

    /// Observe disabled task completion after the caller's normal stop. A
    /// timeout preserves registration and data; it never terminates a task.
    pub fn wait_observed(
        &self,
        spec: &OwnedTaskSpec,
        timeout: Duration,
    ) -> io::Result<Option<TaskStatus>> {
        let deadline = Instant::now() + timeout.min(Duration::from_secs(600));
        loop {
            let status = self.inspect_owned(spec)?;
            match &status {
                None => return Ok(None),
                Some(status) if status.enabled => {
                    return Err(io::Error::other(
                        "Startup admission is still enabled; registration preserved",
                    ));
                }
                Some(status) if !status.is_active() && matches!(status.state, 1 | 3) => {
                    return Ok(Some(status.clone()));
                }
                Some(status) if status.state == 0 => {
                    return Err(io::Error::other(
                        "Startup state is unknown; disabled registration preserved",
                    ));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Owned task has not finished normal shutdown; disabled registration and state preserved",
                ));
            }
            thread::sleep(Duration::from_millis(200));
        }
    }

    /// Delete only an observed disabled, nonactive, still-owned exact task.
    pub fn remove_exact(&self, spec: &OwnedTaskSpec) -> io::Result<()> {
        let Some(status) = self.inspect_owned(spec)? else {
            return Ok(());
        };
        if status.enabled || status.is_active() || !matches!(status.state, 1 | 3) {
            return Err(io::Error::other(
                "Startup task is enabled, active or unknown; registration preserved",
            ));
        }
        unsafe { self.folder.DeleteTask(&BSTR::from(&spec.task_name), 0) }
            .map_err(|e| native_error("Remove exact owned startup task", e))?;
        if self.inspect_owned(spec)?.is_some() {
            return Err(io::Error::other(
                "Startup removal could not be confirmed; inspect exact task",
            ));
        }
        Ok(())
    }

    fn verify_account(&self) -> io::Result<()> {
        if crate::win32::current_user_sid_for_storage()? != self.sid {
            return Err(foreign());
        }
        Ok(())
    }

    fn owned_task(&self, spec: &OwnedTaskSpec) -> io::Result<Option<IRegisteredTask>> {
        match unsafe { self.folder.GetTask(&BSTR::from(&spec.task_name)) } {
            Ok(task) => {
                self.status(spec, &task)?;
                Ok(Some(task))
            }
            Err(error) if error.code().0 == 0x80070002_u32 as i32 => Ok(None),
            Err(error) => Err(native_error("Inspect exact startup task", error)),
        }
    }

    fn status(&self, spec: &OwnedTaskSpec, task: &IRegisteredTask) -> io::Result<TaskStatus> {
        let definition =
            unsafe { task.Definition() }.map_err(|e| native_error("Read startup binding", e))?;
        let binding = read_binding(&definition)?;
        let kind = binding.admit(spec, &self.sid)?;
        let enabled =
            unsafe { task.Enabled() }.map_err(|e| native_error("Read startup admission", e))?;
        let state = unsafe { task.State() }.map_err(|e| native_error("Read startup state", e))?;
        let last =
            unsafe { task.LastTaskResult() }.map_err(|e| native_error("Read startup result", e))?;
        // Disabled admission does not prove an existing instance completed.
        // Query instances only for this exact owned task.
        let active_instance_count = unsafe { task.GetInstances(0).and_then(|tasks| tasks.Count()) }
            .map_err(|e| native_error("Read exact startup task instances", e))?;
        if active_instance_count < 0 {
            return Err(io::Error::other("Invalid startup instance count"));
        }
        Ok(TaskStatus {
            enabled: enabled.0 != 0,
            state: state.0,
            last_task_result: last,
            active_instance_count,
            kind,
            user_sid: self.sid.clone(),
        })
    }
}

fn initialize_process_security() -> io::Result<()> {
    // Match Microsoft's Task Scheduler native-client security setup. COM
    // security is process-wide and can only be initialized once. Do not
    // override or silently accept an earlier incompatible initialization.
    static SECURITY: OnceLock<Result<(), windows::core::HRESULT>> = OnceLock::new();
    let result = SECURITY.get_or_init(|| unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
        .map_err(|error| error.code())
    });
    match result {
        Ok(()) => Ok(()),
        Err(code) => Err(native_error(
            "Initialize process-local Task Scheduler COM security",
            windows::core::Error::from_hresult(*code),
        )),
    }
}

fn read_binding(definition: &ITaskDefinition) -> io::Result<TaskBinding> {
    let read = || -> windows::core::Result<TaskBinding> {
        // Each out pointer targets a live initialized value; COM interfaces
        // own all returned references/BSTRs and release them on scope exit.
        unsafe {
            let registration = definition.RegistrationInfo()?;
            let source = text(|out| registration.Source(out))?;
            let principal = definition.Principal()?;
            let user = text(|out| principal.UserId(out))?;
            let group_id = text(|out| principal.GroupId(out))?;
            let mut run_level = TASK_RUNLEVEL_TYPE::default();
            principal.RunLevel(&mut run_level)?;
            let mut logon = TASK_LOGON_TYPE::default();
            principal.LogonType(&mut logon)?;
            let actions = definition.Actions()?;
            let mut count = 0;
            actions.Count(&mut count)?;
            if count != 1 {
                return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                    0x80070005_u32 as i32,
                )));
            }
            let action = actions.get_Item(1)?;
            let mut action_type = TASK_ACTION_TYPE::default();
            action.Type(&mut action_type)?;
            let exec: IExecAction = action.cast()?;
            let executable = text(|out| exec.Path(out))?;
            let arguments = text(|out| exec.Arguments(out))?;
            let working_directory = text(|out| exec.WorkingDirectory(out))?;
            let triggers = definition.Triggers()?;
            let mut trigger_count = 0;
            triggers.Count(&mut trigger_count)?;
            if trigger_count != 1 {
                return Err(windows::core::Error::from_hresult(windows::core::HRESULT(
                    0x80070005_u32 as i32,
                )));
            }
            let trigger = triggers.get_Item(1)?;
            let mut trigger_type = TASK_TRIGGER_TYPE2::default();
            trigger.Type(&mut trigger_type)?;
            let mut trigger_enabled = VARIANT_BOOL::default();
            trigger.Enabled(&mut trigger_enabled)?;
            let start_boundary = text(|out| trigger.StartBoundary(out))?;
            let end_boundary = text(|out| trigger.EndBoundary(out))?;
            let repetition = trigger.Repetition()?;
            let repetition_interval = text(|out| repetition.Interval(out))?;
            let repetition_duration = text(|out| repetition.Duration(out))?;
            let (trigger_user, trigger_delay) = match trigger_type.0 {
                8 => {
                    let boot: IBootTrigger = trigger.cast()?;
                    (String::new(), text(|out| boot.Delay(out))?)
                }
                9 => {
                    let logon: ILogonTrigger = trigger.cast()?;
                    (
                        text(|out| logon.UserId(out))?,
                        text(|out| logon.Delay(out))?,
                    )
                }
                _ => (String::new(), String::new()),
            };
            let settings = definition.Settings()?;
            let mut terminate = VARIANT_BOOL::default();
            settings.AllowHardTerminate(&mut terminate)?;
            let mut instances = TASK_INSTANCES_POLICY::default();
            settings.MultipleInstances(&mut instances)?;
            let execution_limit = text(|out| settings.ExecutionTimeLimit(out))?;
            let restart_interval = text(|out| settings.RestartInterval(out))?;
            let mut restart_count = 0;
            settings.RestartCount(&mut restart_count)?;
            let mut stop_on_battery = VARIANT_BOOL::default();
            settings.StopIfGoingOnBatteries(&mut stop_on_battery)?;
            let mut disallow_on_battery = VARIANT_BOOL::default();
            settings.DisallowStartIfOnBatteries(&mut disallow_on_battery)?;
            let mut start_when_available = VARIANT_BOOL::default();
            settings.StartWhenAvailable(&mut start_when_available)?;
            let mut network_only = VARIANT_BOOL::default();
            settings.RunOnlyIfNetworkAvailable(&mut network_only)?;
            let mut hidden = VARIANT_BOOL::default();
            settings.Hidden(&mut hidden)?;
            let mut wake = VARIANT_BOOL::default();
            settings.WakeToRun(&mut wake)?;
            let mut demand_start = VARIANT_BOOL::default();
            settings.AllowDemandStart(&mut demand_start)?;
            Ok(TaskBinding {
                source,
                user_sid: user,
                run_level: run_level.0,
                action_count: count,
                action_type: action_type.0,
                executable,
                arguments,
                working_directory,
                logon_type: logon.0,
                trigger_count,
                trigger_type: trigger_type.0,
                trigger_user_sid: trigger_user,
                trigger_enabled: trigger_enabled.0 != 0,
                trigger_delay,
                allow_hard_terminate: terminate.0 != 0,
                instances: instances.0,
                execution_limit,
                restart_interval,
                restart_count,
                stop_on_battery: stop_on_battery.0 != 0,
                disallow_on_battery: disallow_on_battery.0 != 0,
                start_when_available: start_when_available.0 != 0,
                network_only: network_only.0 != 0,
                hidden: hidden.0 != 0,
                wake: wake.0 != 0,
                demand_start: demand_start.0 != 0,
                group_id,
                start_boundary,
                end_boundary,
                repetition_interval,
                repetition_duration,
            })
        }
    };
    let mut binding = read().map_err(|e| native_error("Read exact startup definition", e))?;
    binding.user_sid = resolve_sid(&binding.user_sid)?;
    if !binding.trigger_user_sid.is_empty() {
        binding.trigger_user_sid = resolve_sid(&binding.trigger_user_sid)?;
    }
    Ok(binding)
}

fn text(
    read: impl FnOnce(*mut BSTR) -> windows::core::Result<()>,
) -> windows::core::Result<String> {
    let mut output = BSTR::new();
    read(&mut output)?;
    String::from_utf16(&output).map_err(|_| {
        windows::core::Error::from_hresult(windows::core::HRESULT(0x8007000d_u32 as i32))
    })
}

/// Owns only our BSTR allocation. The caller owns the original borrowed
/// password; COM/RPC/service copies cannot be zeroed by this client.
struct SecretVariant(VARIANT);
impl SecretVariant {
    fn new(password: &str) -> io::Result<Self> {
        if password.contains('\0') || password.encode_utf16().count() > 4096 {
            return Err(invalid("Invalid Windows password length"));
        }
        let wide: Zeroizing<Vec<u16>> = Zeroizing::new(password.encode_utf16().collect());
        Ok(Self(VARIANT::from(BSTR::from_wide(&wide))))
    }
}
impl Drop for SecretVariant {
    fn drop(&mut self) {
        if self.0.vt() == VT_BSTR {
            // This VARIANT exclusively owns the moved BSTR. No references to
            // its content remain here. Zero before VariantClear frees it.
            unsafe {
                let inner = &mut *self.0.Anonymous.Anonymous;
                let bstr = &mut *inner.Anonymous.bstrVal;
                if !bstr.is_empty() {
                    std::slice::from_raw_parts_mut(bstr.as_ptr().cast_mut(), bstr.len()).zeroize();
                }
            }
        }
    }
}

fn native_error(operation: &'static str, error: windows::core::Error) -> io::Error {
    // Never format COM description text: a provider may include credentials or
    // user data in it. Fixed operation plus numeric HRESULT is sufficient.
    io::Error::other(format!(
        "{operation} failed (HRESULT 0x{:08x}); configuration and state preserved",
        error.code().0 as u32
    ))
}

struct LocalSid(*mut std::ffi::c_void);
impl Drop for LocalSid {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

fn account_for_sid(sid: &str) -> io::Result<String> {
    let mut raw = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(sid).as_ptr(), &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = LocalSid(raw);
    let (mut name_len, mut domain_len, mut kind) = (0, 0, 0);
    unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.0,
            std::ptr::null_mut(),
            &mut name_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || name_len == 0
        || name_len > 32768
        || domain_len > 32768
    {
        return Err(io::Error::other("Cannot resolve current startup account"));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountSidW(
            std::ptr::null(),
            sid.0,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let name = String::from_utf16(&name[..name_len as usize])
        .map_err(|_| invalid("Invalid startup account name"))?;
    let domain = String::from_utf16(&domain[..domain_len as usize])
        .map_err(|_| invalid("Invalid startup account domain"))?;
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

fn resolve_sid(account: &str) -> io::Result<String> {
    if crate::is_sid_shape(account) {
        return Ok(account.into());
    }
    if account.is_empty() || account.chars().any(char::is_control) {
        return Err(foreign());
    }
    let account = wide(account);
    let (mut sid_len, mut domain_len, mut kind) = (0, 0, 0);
    unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            std::ptr::null_mut(),
            &mut sid_len,
            std::ptr::null_mut(),
            &mut domain_len,
            &mut kind,
        )
    };
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
        || sid_len == 0
        || sid_len > 1024
        || domain_len > 32768
    {
        return Err(foreign());
    }
    let mut sid = vec![0usize; (sid_len as usize).div_ceil(std::mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_len as usize];
    if unsafe {
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut kind,
        )
    } == 0
    {
        return Err(foreign());
    }
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 {
        return Err(foreign());
    }
    let allocated = LocalSid(text.cast());
    let mut len = 0;
    // A valid SID string is bounded by Windows' maximum SID string length.
    while len < 184 && unsafe { *text.add(len) } != 0 {
        len += 1;
    }
    if len == 184 {
        return Err(foreign());
    }
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(text, len) })
        .map_err(|_| foreign())?;
    drop(allocated);
    if !crate::is_sid_shape(&result) {
        return Err(foreign());
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_definition_roundtrip_is_read_only() {
        // NewTask creates an in-memory definition only. This test never calls
        // GetTask, RegisterTaskDefinition, Run, SetEnabled or DeleteTask.
        let scheduler = TaskScheduler::connect().unwrap();
        let spec = OwnedTaskSpec::new(
            "0123456789abcdef",
            std::path::Path::new(r"C:\Synthetic Raiun\raiun.exe"),
            r#"--config "C:\synthetic\config.json" drive --state-dir "C:\synthetic\state" serve"#,
            std::path::Path::new(r"C:\Synthetic Raiun"),
        )
        .unwrap();
        for kind in [StartupKind::Boot, StartupKind::Logon] {
            let definition = unsafe { scheduler.service.NewTask(0) }.unwrap();
            let xml = BSTR::from(spec.definition_xml(kind, scheduler.current_sid()).unwrap());
            unsafe { definition.SetXmlText(&xml) }.unwrap();
            let binding = read_binding(&definition).unwrap();
            assert_eq!(binding.admit(&spec, scheduler.current_sid()).unwrap(), kind);
        }
    }
}
