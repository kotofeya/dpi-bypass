//! Shared, hot-swappable strategy profile. The prober `store()`s a new Arc<Profile>;
//! the packet engine calls `load_full()` per packet.

use arc_swap::ArcSwap;
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum SplitAt {
    /// absolute byte offset inside the TCP payload
    Fixed(usize),
    /// middle of the SNI hostname
    SniMid,
}

impl SplitAt {
    /// Resolve to a split index in 1..=len-1.
    pub fn resolve(self, sni_off: usize, sni_len: usize, len: usize) -> usize {
        let p = match self {
            SplitAt::Fixed(n) => n,
            SplitAt::SniMid => sni_off + sni_len / 2,
        };
        p.clamp(1, len.saturating_sub(1).max(1))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// split at byte 1 and prepend a fake ClientHello in already-acknowledged sequence space
    /// ("multisplit + seqovl" in zapret): needs no fooling, the server drops the fake bytes
    SeqOvl,
    /// `fake_count` fakes, then the original data untouched (zapret "fake")
    Fake,
    /// fakes, then the real data split in two, optionally reversed (zapret "fake,multidisorder")
    FakeSplit,
}

/// How a fake is kept away from the server while the DPI still reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fooling {
    /// IP TTL low enough to expire between the DPI and the server
    Ttl(u8),
    /// broken TCP/UDP checksum
    BadSum,
    /// sequence/ack numbers far outside the server's window (zapret "badseq")
    BadSeq,
}

#[derive(Clone, Debug)]
pub struct Profile {
    // ---- TCP/TLS ----
    pub method: Method,
    pub split: SplitAt,
    pub disorder: bool,
    pub fooling: Fooling,
    pub fake_count: u8,
    pub fake_sni: String,
    // ---- UDP ----
    pub discord_fakes: u8,
    pub drop_quic: bool,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            method: Method::SeqOvl,
            split: SplitAt::SniMid,
            disorder: true,
            fooling: Fooling::BadSeq,
            fake_count: 6,
            fake_sni: "www.google.com".into(),
            discord_fakes: 6,
            drop_quic: true,
        }
    }
}

pub type Shared = Arc<ArcSwap<Profile>>;

pub fn shared_default() -> Shared {
    Arc::new(ArcSwap::from_pointee(Profile::default()))
}

/// Hosts that get desync (suffix match). YouTube plus the Discord list used by
/// zapret-discord-youtube.
const TARGETS: &[&str] = &[
    // YouTube / Google video
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
    "youtubekids.com", "youtube.googleapis.com", "youtubei.googleapis.com",
    "youtubeembeddedplayer.googleapis.com", "jnn-pa.googleapis.com", "yt3.googleusercontent.com",
    "wide-youtube.l.google.com", "youtube-ui.l.google.com", "yt-video-upload.l.google.com",
    "ytimg.l.google.com", "play.google.com", "fonts.googleapis.com", "www.gstatic.com",
    // Discord
    "discord.com", "discord.gg", "discord.app", "discord.co", "discord.design", "discord.dev",
    "discord.gift", "discord.gifts", "discord.media", "discord.new", "discord.store",
    "discord.status", "discordapp.com", "discordapp.net", "discordcdn.com", "discordstatus.com",
    "discord-activities.com", "discordactivities.com", "discordmerch.com", "discordpartygames.com",
    "discordsays.com", "discordsez.com", "dis.gd", "discord-attachments-uploads-prd.storage.googleapis.com",
    // Cloudflare front / ECH used by Discord
    "cloudflare-ech.com", "encryptedsni.com",
];
/// Google-hosted names: their fake pattern carries www.google.com (as zapret's list-google).
const GOOGLE: &[&str] = &[
    "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com",
    "youtubekids.com", "googleapis.com", "googleusercontent.com", "google.com", "gstatic.com",
];

fn matches(host: &str, list: &[&str]) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    list.iter().any(|s| h == *s || (h.len() > s.len() && h.ends_with(s) && h.as_bytes()[h.len() - s.len() - 1] == b'.'))
}
pub fn is_target(host: &str) -> bool { matches(host, TARGETS) }
pub fn is_google(host: &str) -> bool { matches(host, GOOGLE) }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_matching() {
        assert!(is_target("gateway.discord.gg"));
        assert!(is_target("updates.discord.com"));
        assert!(is_target("rr3---sn-abc.googlevideo.com"));
        assert!(is_target("WWW.YouTube.com."));
        assert!(!is_target("notdiscord.com"));
        assert!(!is_target("web.telegram.org"));
        assert!(is_target("c-abc123.discord.media") && is_target("cdn.discordapp.com"));
        assert!(is_google("rr1---sn-x.googlevideo.com") && !is_google("discord.com"));
    }

    #[test]
    fn split_resolution() {
        assert_eq!(SplitAt::SniMid.resolve(100, 20, 500), 110);
        assert_eq!(SplitAt::Fixed(1000).resolve(0, 0, 500), 499);
        assert_eq!(SplitAt::Fixed(0).resolve(0, 0, 500), 1);
    }
}
