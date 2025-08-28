use core::fmt;
use std::collections::BTreeMap;
use std::io;

#[derive(Debug)]
pub struct Udev {
    properties_list: BTreeMap<String, String>,
    sys_path: Path,
    dev_path: Path,
    run_path: Path,
    rules: Rules,
    log_priority: LogPriority,
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogPriority {
    Error,
    Info,
    #[default]
    Debug,
}

impl LogPriority {
    fn try_from_value(val: &str) -> Option<Self> {
        Some(match val {
            "err" => Self::Error,
            "info" => Self::Info,
            "debug" => Self::Debug,
            _ => return None,
        })
    }
}

pub(crate) enum Path {
    Custom(String),
    Default(&'static str),
}

impl AsRef<str> for Path {
    fn as_ref(&self) -> &str {
        match self {
            Self::Custom(c) => c,
            Self::Default(d) => d,
        }
    }
}

impl fmt::Debug for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(c) => write!(f, "{c:?}"),
            Self::Default(d) => write!(f, "{d:?}"),
        }
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Custom(c) => write!(f, "{c}"),
            Self::Default(d) => write!(f, "{d}"),
        }
    }
}

impl Udev {
    pub fn new() -> io::Result<Self> {
        use std::env;
        use std::fs;
        const SYS_CONF_DIR: &str = "/etc";
        const CONFIG_FILE: &str = "UDEV_CONFIG_FILE";

        let mut custom_file = false;

        let mut properties_list = BTreeMap::new();

        let config_file_path = env::var_os(CONFIG_FILE)
            .inspect(|_| {
                custom_file = true;
            })
            .unwrap_or(const_format::concatcp!(SYS_CONF_DIR, "/udev/udev.conf").into());

        if custom_file {
            properties_list.insert(
                "UDEV_CONFIG_FILE".into(),
                config_file_path.clone().into_string().unwrap(),
            );
        }

        let mut log_priority = env::var("UDEV_LOG")
            .ok()
            .and_then(|priority| LogPriority::try_from_value(&priority));
        /*
        .map(|priority| LogPriority::try_from_value(&priority))
        .flatten();
        */
        let mut dev_path = None;
        let mut sys_path = None;
        let mut run_path = None;

        let mut rules = None;

        use io::BufRead;

        if let Ok(f) = fs::OpenOptions::new().read(true).open(config_file_path) {
            let reader = io::BufReader::new(f);

            for line in reader.lines() {
                let line = line?;
                let line = line.trim();

                if line.is_empty() || line.starts_with('#') {
                    // comment
                    continue;
                }

                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };

                let key = key.trim();
                let mut value = value.trim();

                if value.starts_with('\'') || value.starts_with('"') {
                    if value.len() == 1
                        || (value[..1].chars().next() != value[value.len() - 1..].chars().next())
                    {
                        // inconsistent quoting
                        continue;
                    }
                    // remove quotes
                    value = &value[1..value.len() - 1];
                }

                if value.is_empty() {
                    continue;
                }

                match key {
                    "udev_log" => {
                        if log_priority.is_none() {
                            log_priority = LogPriority::try_from_value(value);
                        }
                    }
                    "udev_root" => dev_path = Some(Path::Custom(value.to_owned())),
                    "udev_run" => run_path = Some(Path::Custom(value.to_owned())),
                    "udev_sys" => sys_path = Some(Path::Custom(value.to_owned())),
                    "udev_rules" => rules = Some(Rules::Custom(value.to_owned())),
                    // unknown key
                    _ => continue,
                }
            }
        }
        const DEV_PATH: &str = "/dev";
        const SYS_PATH: &str = "/sys";
        const RUN_PATH: &str = "/run/udev";

        let dev_path = dev_path.unwrap_or(Path::Default(DEV_PATH));
        let sys_path = sys_path.unwrap_or(Path::Default(SYS_PATH));
        let run_path = run_path.unwrap_or(Path::Default(RUN_PATH));

        let rules = rules.unwrap_or({
            const PKG_EXEC_DIR: &str = "/lib/udev";
            let default_rules = DefaultRules {
                _system: const_format::concatcp!(PKG_EXEC_DIR, "/rules.d"),
                _local_admin: const_format::concatcp!(SYS_CONF_DIR, "/udev/rules.d"),
                _runtime: format!("{}/rules.d", run_path),
            };
            Rules::Default(default_rules)
        });

        Ok(Self {
            properties_list,
            sys_path,
            dev_path,
            run_path,
            rules,
            log_priority: log_priority.unwrap_or_default(),
        })
    }

    pub fn set_log_priority(&mut self, priority: LogPriority) {
        self.log_priority = priority;
    }

    pub fn get_log_priority(&self) -> LogPriority {
        self.log_priority
    }

    pub fn sys_path(&self) -> &str {
        self.sys_path.as_ref()
    }

    pub fn dev_path(&self) -> &str {
        self.dev_path.as_ref()
    }

    pub fn run_path(&self) -> &str {
        self.run_path.as_ref()
    }

    pub fn add_property(&mut self, key: String, value: String) -> Option<String> {
        self.properties_list.insert(key, value)
    }

    pub fn remove_property(&mut self, key: &str) -> Option<String> {
        self.properties_list.remove(key)
    }

    pub fn get_property(&self, key: &str) -> Option<&str> {
        self.properties_list.get(key).map(|s| s.as_ref())
    }

    pub fn custom_rules_path(&self) -> Option<&str> {
        self.rules.custom_path()
    }

    pub fn default_rules(&self) -> Option<&DefaultRules> {
        match &self.rules {
            Rules::Default(d) => Some(d),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum Rules {
    Custom(String),
    Default(DefaultRules),
}

impl Rules {
    pub(crate) fn custom_path(&self) -> Option<&str> {
        match self {
            Self::Custom(s) => Some(s),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct DefaultRules {
    _system: &'static str,
    _local_admin: &'static str,
    _runtime: String,
}
