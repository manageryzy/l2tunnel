use super::*;
use l2tunnel_security::{LaneId, Limits, Purpose, Role, SessionBinding, SessionRoot, compact};
use ring::{digest, hkdf};
use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub struct Config {
    pub role: String,
    pub tun: String,
    pub netns: String,
    pub local: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub local_port: u16,
    pub peer_port: u16,
    pub n: u8,
    pub path_arq: bool,
    pub fair_members: bool,
    pub physical_rank_suppression: bool,
    pub transfer_named_path_debt: bool,
    pub pace_original_frontiers: bool,
    pub(super) native_mode: native::Mode,
    pub paced_recovery: bool,
    pub authenticated_path_ready: bool,
    pub low_load_forward_round: bool,
    pub wire_rate_bps: Option<u64>,
    pub pacing_burst_frames: u8,
    pub pacing_timer_slack_ns: Option<std::num::NonZeroU64>,
    pub a3_request_copies: u8,
    pub a3_reply_copies: u8,
    pub k: u8,
    pub mtu: u16,
    pub hold: u64,
    pub stats: PathBuf,
    pub trace: Option<PathBuf>,
    pub trace_scheduler_groups: Option<trace::ScheduleRange>,
    key: PathBuf,
}

fn component(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

impl Config {
    pub fn read() -> Result<Self> {
        let mut values = BTreeMap::new();
        let mut path_arq = false;
        let mut fair_members = false;
        let mut physical_rank_suppression = false;
        let mut transfer_named_path_debt = false;
        let mut pace_original_frontiers = false;
        let mut native_mode = native::Mode::Independent;
        let mut paced_recovery = false;
        let mut authenticated_path_ready = false;
        let mut low_load_forward_round = false;
        let mut args = std::env::args().skip(1);
        while let Some(key) = args.next() {
            if matches!(key.as_str(), "--ordered-native" | "--ordered-tcp-data") {
                if native_mode != native::Mode::Independent {
                    return Err("select only one native delivery mode".into());
                }
                native_mode = if key == "--ordered-native" {
                    native::Mode::Ordered
                } else {
                    native::Mode::OrderedTcpData
                };
                continue;
            }
            if key == "--path-arq" {
                if path_arq {
                    return Err("repeated path ARQ flag".into());
                }
                path_arq = true;
                continue;
            }
            if key == "--transfer-named-path-debt" {
                if transfer_named_path_debt {
                    return Err("repeated named path debt transfer flag".into());
                }
                transfer_named_path_debt = true;
                continue;
            }
            if key == "--low-load-forward-round" {
                if low_load_forward_round {
                    return Err("repeated low-load forward round flag".into());
                }
                low_load_forward_round = true;
                continue;
            }
            if key == "--authenticated-path-ready" {
                if authenticated_path_ready {
                    return Err("repeated authenticated path-ready flag".into());
                }
                authenticated_path_ready = true;
                continue;
            }
            if key == "--paced-recovery" {
                if paced_recovery {
                    return Err("repeated paced recovery flag".into());
                }
                paced_recovery = true;
                continue;
            }
            if key == "--pace-original-frontiers" {
                if pace_original_frontiers {
                    return Err("repeated original frontier pacing flag".into());
                }
                pace_original_frontiers = true;
                continue;
            }
            if key == "--physical-rank-suppression" {
                if physical_rank_suppression {
                    return Err("repeated physical rank suppression flag".into());
                }
                physical_rank_suppression = true;
                continue;
            }
            if key == "--fair-members" {
                if fair_members {
                    return Err("repeated fair members flag".into());
                }
                fair_members = true;
                continue;
            }
            if values
                .insert(key, args.next().ok_or("missing flag value")?)
                .is_some()
            {
                return Err("repeated flag".into());
            }
        }
        if transfer_named_path_debt && !(physical_rank_suppression && path_arq && fair_members) {
            return Err("--transfer-named-path-debt requires --physical-rank-suppression, --path-arq and --fair-members".into());
        }
        if low_load_forward_round
            && !(paced_recovery && fair_members && path_arq && physical_rank_suppression)
        {
            return Err("--low-load-forward-round requires --paced-recovery, --fair-members, --path-arq and --physical-rank-suppression".into());
        }
        if authenticated_path_ready && !paced_recovery {
            return Err("--authenticated-path-ready requires --paced-recovery".into());
        }
        if physical_rank_suppression && !(path_arq && fair_members) {
            return Err(
                "--physical-rank-suppression requires --path-arq and --fair-members".into(),
            );
        }
        if pace_original_frontiers && !(paced_recovery && fair_members) {
            return Err(
                "--pace-original-frontiers requires --paced-recovery and --fair-members".into(),
            );
        }
        let a3_request_copies = values
            .remove("--a3-request-copies")
            .as_deref()
            .unwrap_or("1")
            .parse()?;
        let a3_reply_copies = values
            .remove("--a3-reply-copies")
            .as_deref()
            .unwrap_or("1")
            .parse()?;
        let n: u8 = values.remove("--paths").as_deref().unwrap_or("6").parse()?;
        let wire_rate_bps = values
            .remove("--wire-rate-bps")
            .map(|v| v.parse::<u64>())
            .transpose()?;
        let pacing_burst_frames = values
            .remove("--pacing-burst-frames")
            .map(|v| v.parse::<u8>())
            .transpose()?;
        if let Some(frames) = pacing_burst_frames
            && (!paced_recovery || !(1..=pacing::MAX_BURST_FRAMES).contains(&frames))
        {
            return Err("--pacing-burst-frames requires --paced-recovery and 1..=8 frames".into());
        }
        if paced_recovery != wire_rate_bps.is_some() || wire_rate_bps == Some(0) {
            return Err(
                "paced recovery requires a positive --wire-rate-bps and both options together"
                    .into(),
            );
        }
        let pacing_timer_slack_ns = values
            .remove("--pacing-timer-slack-ns")
            .map(|value| value.parse::<std::num::NonZeroU64>())
            .transpose()?;
        if pacing_timer_slack_ns.is_some() && !paced_recovery {
            return Err("--pacing-timer-slack-ns requires --paced-recovery".into());
        }
        let trace = values.remove("--trace").map(PathBuf::from);
        let trace_scheduler_groups = values
            .remove("--trace-scheduler-groups")
            .map(|value| value.parse())
            .transpose()?;
        if trace_scheduler_groups.is_some() && !(trace.is_some() && paced_recovery && fair_members)
        {
            return Err(
                "--trace-scheduler-groups requires --trace, --paced-recovery and --fair-members"
                    .into(),
            );
        }
        let mut take = |key: &str| values.remove(key).ok_or_else(|| format!("missing {key}"));
        let cfg = Self {
            n,
            path_arq,
            fair_members,
            physical_rank_suppression,
            transfer_named_path_debt,
            pace_original_frontiers,
            native_mode,
            paced_recovery,
            authenticated_path_ready,
            low_load_forward_round,
            wire_rate_bps,
            pacing_burst_frames: pacing_burst_frames.unwrap_or(1),
            pacing_timer_slack_ns,
            a3_request_copies,
            a3_reply_copies,
            trace,
            trace_scheduler_groups,
            tun: take("--tun")?,
            netns: take("--netns")?,
            role: take("--role")?,
            local: take("--local-ip")?.parse()?,
            peer: take("--peer-ip")?.parse()?,
            local_port: take("--local-port")?.parse()?,
            peer_port: take("--peer-port")?.parse()?,
            k: take("--threshold")?.parse()?,
            mtu: take("--mtu")?.parse()?,
            hold: take("--hold-us")?.parse()?,
            stats: take("--stats")?.into(),
            key: take("--key-file")?.into(),
        };
        if !values.is_empty()
            || !matches!(cfg.role.as_str(), "client" | "server")
            || !(1..=cfg.n).contains(&cfg.a3_request_copies)
            || !(1..=cfg.n).contains(&cfg.a3_reply_copies)
            || cfg.k == 0
            || cfg.k > cfg.n
            || !(600..=1500).contains(&cfg.mtu)
            || !(1..=10_000).contains(&cfg.hold)
            || !component(&cfg.tun)
            || !component(&cfg.netns)
            || cfg.local == cfg.peer
            || cfg.local_port == 0
            || cfg.peer_port == 0
            || cfg.local_port > u16::MAX - u16::from(cfg.n.saturating_sub(1))
            || cfg.peer_port > u16::MAX - u16::from(cfg.n.saturating_sub(1))
        {
            return Err("invalid explicit Linux path-bundle lab configuration".into());
        }
        let ns = |p: &Path| -> std::io::Result<(u64, u64)> {
            let m = std::fs::metadata(p)?;
            Ok((m.dev(), m.ino()))
        };
        let here = ns(Path::new("/proc/self/ns/net"))?;
        if here == ns(Path::new("/proc/1/ns/net"))?
            || here != ns(&Path::new("/run/netns").join(&cfg.netns))?
        {
            return Err("requires the explicitly named isolated network namespace".into());
        }
        let flags =
            std::fs::read_to_string(Path::new("/sys/class/net").join(&cfg.tun).join("tun_flags"))?;
        if u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)? & 3 != 1 {
            return Err("requires a pre-created IFF_TUN device in the selected namespace".into());
        }
        Ok(cfg)
    }

    pub fn readiness(&self, start_us: u64) -> Result<Option<readiness::State>> {
        if !self.authenticated_path_ready {
            return Ok(None);
        }
        use ring::rand::{SecureRandom, SystemRandom};
        let rng = SystemRandom::new();
        let mut challenges = vec![[0; 16]; usize::from(self.n)];
        for challenge in &mut challenges {
            rng.fill(challenge)
                .map_err(|_| "path challenge entropy unavailable")?;
        }
        Ok(Some(readiness::State::new(challenges, start_us)?))
    }

    pub fn sockets(&self) -> Result<Vec<UdpSocket>> {
        (0..u16::from(self.n))
            .map(|i| {
                let sock = UdpSocket::bind(SocketAddrV4::new(self.local, self.local_port + i))?;
                sock.connect(SocketAddrV4::new(self.peer, self.peer_port + i))?;
                sock.set_nonblocking(true)?;
                Ok(sock)
            })
            .collect()
    }

    pub fn security(
        &self,
    ) -> Result<(
        compact::Sender,
        compact::Receiver,
        sec::ConfigDigest,
        FecContext,
    )> {
        let file = std::fs::File::open(&self.key)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.len() != 32 || meta.mode() & 0o077 != 0 {
            return Err("requires a private 32-byte per-run lab key file".into());
        }
        use std::io::Read;
        let mut secret = Zeroizing::new([0u8; 32]);
        (&file).read_exact(&mut *secret)?;
        // Each role consumes this fixture once. The harness generates a new random key per run.
        let mut consumed = self.key.as_os_str().to_owned();
        consumed.push(format!(".{}.used", self.role));
        std::fs::File::create_new(consumed)?;
        let client = self.role == "client";
        let local = SocketAddrV4::new(self.local, self.local_port);
        let remote = SocketAddrV4::new(self.peer, self.peer_port);
        let (a, b) = if client {
            (local, remote)
        } else {
            (remote, local)
        };
        let profile = format!(
            "path-bundle-netns-v1/{a}/{b}/{}/{}/{}/{}",
            self.n, self.k, self.mtu, self.hold
        );
        let profile = if self.a3_reply_copies == 1 && self.a3_request_copies == 1 {
            profile
        } else {
            format!(
                "{profile}/a3/{}/{}",
                self.a3_request_copies, self.a3_reply_copies
            )
        };
        let profile = if self.path_arq {
            format!("{profile}/path-arq/256/3/90000")
        } else {
            profile
        };
        let profile = if self.fair_members {
            format!("{profile}/fair-members-v1")
        } else {
            profile
        };
        let profile = if self.physical_rank_suppression {
            format!("{profile}/physical-rank-suppression-v1")
        } else {
            profile
        };
        // The local direction has its own rate. Both peers bind the common policy identity.
        let profile = if self.paced_recovery {
            format!("{profile}/paced-recovery-v1")
        } else {
            profile
        };
        // One frame retains the established profile identity.
        let profile = if self.pacing_burst_frames > 1 {
            format!("{profile}/burst-frames/{}", self.pacing_burst_frames)
        } else {
            profile
        };
        let profile = if self.pace_original_frontiers {
            format!("{profile}/pace-original-frontiers-v1")
        } else {
            profile
        };
        let profile = match self.native_mode {
            native::Mode::Independent => profile,
            native::Mode::Ordered => format!("{profile}/ordered-native-v1"),
            native::Mode::OrderedTcpData => format!("{profile}/ordered-tcp-data-v1"),
        };
        let profile = if self.authenticated_path_ready {
            format!("{profile}/authenticated-path-ready-v1")
        } else {
            profile
        };
        let profile = if self.low_load_forward_round {
            format!("{profile}/low-load-forward-round-v2/128/35000/1")
        } else {
            profile
        };
        let profile = if self.transfer_named_path_debt {
            format!("{profile}/transfer-named-path-debt-v1")
        } else {
            profile
        };
        let hash: [u8; 32] = digest::digest(&digest::SHA256, profile.as_bytes())
            .as_ref()
            .try_into()?;
        let key = hkdf::Salt::new(hkdf::HKDF_SHA256, &hash).extract(&secret[..]);
        let derive = |label: &[u8]| -> Result<Zeroizing<[u8; 32]>> {
            let mut out = Zeroizing::new([0; 32]);
            key.expand(&[label], hkdf::HKDF_SHA256)
                .map_err(|_| "invalid HKDF")?
                .fill(&mut out[..])
                .map_err(|_| "invalid HKDF output")?;
            Ok(out)
        };
        let session: [u8; 16] = derive(b"private-lab-session")?[..16].try_into()?;
        let role = if client {
            Role::Initiator
        } else {
            Role::Responder
        };
        let mut root = SessionRoot::from_split_keys(
            derive(b"private-lab-forward")?,
            derive(b"private-lab-reverse")?,
            SessionBinding {
                session: sec::SessionId(session),
                transcript: hash,
            },
            role,
        )?;
        let limits = Limits {
            max_body_bytes: usize::from(self.mtu),
            packets_per_key: 1 << 20,
            max_body_bytes_per_key: 1 << 32,
        };
        let selection = compact::Selection {
            max_forward_packets: 1 << 18,
            max_failed_checks: 4096,
        };
        let suite = compact::Protection::ChaCha20Poly1305;
        Ok((
            root.compact_sender(Purpose::Data, LaneId(0), limits, suite, selection)?,
            root.compact_receiver(Purpose::Data, LaneId(0), limits, suite, selection)?,
            sec::ConfigDigest(hash),
            FecContext {
                session: l2tunnel_fec::SessionId(session),
                epoch: l2tunnel_fec::Epoch(0),
                channel: l2tunnel_fec::ChannelId(0),
                direction: if client {
                    l2tunnel_fec::Direction::ServerToClient
                } else {
                    l2tunnel_fec::Direction::ClientToServer
                },
            },
        ))
    }
}
