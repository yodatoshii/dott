use clap::Parser;
use colored::*;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use futures::future::join_all;
use reqwest::Client;
use std::{fs, io::{self, BufRead, IsTerminal, Write}, path::PathBuf, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "dott", version, about = "private domain search. no middlemen.")]
struct Cli {
    name: Option<String>,
    #[arg(short, long)]
    tlds: Option<String>,
    #[arg(short, long, num_args = 1..)]
    suggest: Option<Vec<String>>,
    #[arg(long)]
    plain: bool,
    #[arg(long, value_name = "DOMAIN")]
    watch: Option<String>,
    #[arg(long, value_name = "DOMAIN")]
    unwatch: Option<String>,
    #[arg(long)]
    watching: bool,
    #[arg(long, hide = true)]
    background_check: bool,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct WatchEntry {
    domain: String,
    last_status: String,
}

#[derive(Debug, Clone, Default)]
struct DomainDates {
    registered: Option<String>,
    updated:    Option<String>,
    expires:    Option<String>,
}

#[derive(Debug, Clone)]
enum Availability {
    Available,
    Protected,
    Taken(DomainDates),
    Unknown,
}

impl Availability {
    fn as_str(&self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Protected => "protected",
            Availability::Taken(_)  => "taken",
            Availability::Unknown   => "unknown",
        }
    }
}

// find the first YYYY-MM-DD pattern in a string
fn parse_date(s: &str) -> Option<String> {
    let b = s.as_bytes();
    for i in 0..b.len().saturating_sub(9) {
        if b[i..i+4].iter().all(|c| c.is_ascii_digit())
            && b[i+4] == b'-'
            && b[i+5..i+7].iter().all(|c| c.is_ascii_digit())
            && b[i+7] == b'-'
            && b[i+8..i+10].iter().all(|c| c.is_ascii_digit())
        {
            return Some(s[i..i+10].to_string());
        }
    }
    None
}

const ALL_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me",
    "so", "gg", "cc", "cv", "xyz",
];

fn tld_rank(domain: &str) -> u8 {
    let tld = domain.rsplit('.').next().unwrap_or("");
    match tld {
        "com" => 0, "io"  => 1, "dev" => 2, "ai"  => 3,
        "app" => 4, "co"  => 5, "net" => 6, "org" => 7,
        "me"  => 8, "so"  => 9, "gg"  => 10, "cc" => 11,
        "xyz" => 12, "cv" => 13, _ => 99,
    }
}

// short names in these TLDs are almost always registrar-priced as premium (e.g. go.ai = $20k+).
// heuristic only — RDAP/WHOIS will still say "available", but checkout will hit the user with a surprise.
fn is_likely_premium(domain: &str) -> bool {
    let Some((name, tld)) = domain.rsplit_once('.') else { return false };
    name.len() <= 4 && matches!(tld, "ai" | "io" | "app" | "dev" | "co")
}

fn tld_price(tld: &str) -> Option<&'static str> {
    // Registration prices from Porkbun, April 2026
    match tld {
        "com" => Some("$11.08"), "net" => Some("$12.52"), "org" => Some("$10.74"),
        "io"  => Some("$51.80"), "dev" => Some("$12.87"), "app" => Some("$14.93"),
        "co"  => Some("$25.03"), "ai"  => Some("$82.70"), "me"  => Some("$17.27"),
        "so"  => Some("€55.22"), "gg"  => Some("$51.80"), "cc"  => Some("$8.55"),
        "xyz" => Some("$12.98"), "cv"  => Some("$8.03"),
        _ => None,
    }
}

fn rdap_url(name: &str, tld: &str) -> Option<String> {
    match tld {
        "com"      => Some(format!("https://rdap.verisign.com/com/v1/domain/{}.{}", name, tld)),
        "net"      => Some(format!("https://rdap.verisign.com/net/v1/domain/{}.{}", name, tld)),
        "org"      => Some(format!("https://rdap.publicinterestregistry.org/rdap/domain/{}.{}", name, tld)),
        "io"       => Some(format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld)),
        "dev"      => Some(format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld)),
        "app"      => Some(format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld)),
        "ai"       => Some(format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld)),
        "me"       => Some(format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld)),
        "cc"       => Some(format!("https://tld-rdap.verisign.com/cc/v1/domain/{}.{}", name, tld)),
        "xyz"      => Some(format!("https://rdap.centralnic.com/xyz/domain/{}.{}", name, tld)),
        "cv"       => Some(format!("https://rdap.nic.cv/domain/{}.{}", name, tld)),
        "gg"       => None, // rdap.gg returns HTML — use WHOIS only
        _          => Some(format!("https://rdap.org/domain/{}.{}", name, tld)),
    }
}

fn whois_server(tld: &str) -> Option<&'static str> {
    match tld {
        // only list servers confirmed working — dead servers cause 4s timeouts
        "com"      => Some("whois.verisign-grs.com"),
        "net"      => Some("whois.verisign-grs.com"),
        "org"      => Some("whois.pir.org"),
        "io"       => Some("whois.nic.io"),
        "co"       => Some("whois.registry.co"),
        "ai"       => Some("whois.nic.ai"),
        "me"       => Some("whois.nic.me"),
        "so"       => Some("whois.nic.so"),
        "cc"       => Some("whois.nic.cc"),
        "xyz"      => Some("whois.nic.xyz"),
        "gg"       => Some("whois.gg"),
        _          => None,
    }
}

async fn whois_check(name: &str, tld: &str) -> Availability {
    let server = match whois_server(tld) {
        Some(s) => s,
        None    => return Availability::Unknown,
    };
    let addr  = format!("{}:43", server);
    let query = format!("{}.{}\r\n", name, tld);

    // some registries (e.g. whois.registry.co) are slow to accept — give them more time
    let connect_secs = match server {
        "whois.registry.co" => 8,
        _ => 4,
    };

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(connect_secs),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _         => return Availability::Unknown,
    };

    // CentralNic (whois.registry.co) sends a banner on connect — drain it before querying
    if server == "whois.registry.co" {
        let mut banner = vec![0u8; 512];
        let _ = tokio::time::timeout(
            Duration::from_millis(300),
            stream.read(&mut banner),
        ).await;
    }

    if stream.write_all(query.as_bytes()).await.is_err() {
        return Availability::Unknown;
    }

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(8),
        stream.read_to_string(&mut response),
    ).await;

    let lower = response.to_lowercase();
    if lower.contains("no match")
        || lower.contains("not found")
        || lower.contains("no entries found")
        || lower.contains("object does not exist")
        || lower.contains("domain not found")
        || lower.contains("available")
    {
        Availability::Available
    } else if lower.contains("domain name:") || lower.contains("domain:") {
        let extract = |keyword: &str| -> Option<String> {
            response.lines()
                .find(|l| l.to_lowercase().contains(keyword))
                .and_then(|l| l.find(':').map(|i| &l[i+1..]))
                .and_then(|s| parse_date(s.trim()))
        };
        Availability::Taken(DomainDates {
            registered: extract("creat").or_else(|| extract("registered:")),
            updated:    extract("updat").or_else(|| extract("last modified").or_else(|| extract("changed:"))),
            expires:    extract("expir").or_else(|| extract("paid-till")).or_else(|| extract("renewal")),
        })
    } else {
        Availability::Unknown
    }
}

async fn dns_check(client: &Client, name: &str, tld: &str) -> Availability {
    let url = format!("https://cloudflare-dns.com/dns-query?name={}.{}&type=NS", name, tld);
    let res = client
        .get(&url)
        .header("Accept", "application/dns-json")
        .timeout(Duration::from_secs(4))
        .send().await;
    match res {
        Ok(r) => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            match json["Status"].as_i64() {
                Some(0) => Availability::Taken(DomainDates::default()),  // has NS records = registered
                Some(3) => Availability::Unknown, // NXDOMAIN = not registered
                _       => Availability::Unknown,
            }
        }
        Err(_) => Availability::Unknown,
    }
}

async fn http_query(client: &Client, url: &str, sem: &Semaphore) -> Availability {
    let _permit = sem.acquire().await.unwrap();
    match client.get(url).header("User-Agent", "Mozilla/5.0").header("Accept", "application/json").timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            match status {
                200 => {
                    let dates = serde_json::from_str::<serde_json::Value>(&body).ok()
                        .and_then(|j| j["events"].as_array().cloned())
                        .map(|events| {
                            let find = |keyword: &str| -> Option<String> {
                                events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a == keyword)
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(|d| parse_date(d))
                            };
                            DomainDates {
                                registered: find("registration"),
                                updated:    find("last changed"),
                                expires:    events.iter()
                                    .find(|e| e["eventAction"].as_str()
                                        .map(|a| a.contains("expir"))
                                        .unwrap_or(false))
                                    .and_then(|e| e["eventDate"].as_str())
                                    .and_then(|d| parse_date(d)),
                            }
                        })
                        .unwrap_or_default();
                    Availability::Taken(dates)
                }
                404 => {
                    if body.contains("Blocked") || body.contains("blocked") {
                        Availability::Protected
                    } else {
                        Availability::Available
                    }
                }
                _ => Availability::Unknown,
            }
        }
        Err(_) => Availability::Unknown,
    }
}

fn merge_dates(a: DomainDates, b: DomainDates) -> DomainDates {
    DomainDates {
        registered: a.registered.or(b.registered),
        updated:    a.updated.or(b.updated),
        expires:    a.expires.or(b.expires),
    }
}

fn merge_results(rdap: Availability, whois: Availability, dns: Availability) -> Availability {
    // DNS Taken (active NS records) = definitely registered; pull dates from RDAP/WHOIS if present
    if matches!(dns, Availability::Taken(_)) {
        let dates = match (rdap, whois) {
            (Availability::Taken(a), Availability::Taken(b)) => merge_dates(a, b),
            (Availability::Taken(a), _) => a,
            (_, Availability::Taken(b)) => b,
            _ => DomainDates::default(),
        };
        return Availability::Taken(dates);
    }

    let rdap_vs_whois = match (rdap, whois) {
        (Availability::Unknown, whois)                     => whois,
        (Availability::Taken(a), Availability::Taken(b))   => Availability::Taken(merge_dates(a, b)),
        (rdap, _)                                          => rdap,
    };

    match rdap_vs_whois {
        Availability::Unknown => dns,
        other => other,
    }
}

// 60s in-session cache, keyed on (name, tld). Avoids re-fetching when interactive searches overlap
// (e.g. typing `foo` then `foo+` would otherwise re-query foo.com/io/dev/app/co).
type Cache = Arc<std::sync::Mutex<std::collections::HashMap<(String, &'static str), (std::time::Instant, Availability)>>>;

const CACHE_TTL: Duration = Duration::from_secs(60);

fn new_cache() -> Cache {
    Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()))
}

async fn check_domain_cached(
    client: Client,
    name: String,
    tld: &'static str,
    sem: Arc<Semaphore>,
    cache: Option<Cache>,
) -> (String, Availability) {
    if let Some(ref c) = cache {
        if let Ok(map) = c.lock() {
            if let Some((t, av)) = map.get(&(name.clone(), tld)) {
                if t.elapsed() < CACHE_TTL {
                    return (format!("{}.{}", name, tld), av.clone());
                }
            }
        }
    }
    let (domain, av) = check_domain(client, name.clone(), tld, sem).await;
    if let Some(ref c) = cache {
        if let Ok(mut map) = c.lock() {
            map.insert((name, tld), (std::time::Instant::now(), av.clone()));
        }
    }
    (domain, av)
}

async fn check_domain(client: Client, name: String, tld: &'static str, sem: Arc<Semaphore>) -> (String, Availability) {
    let domain = format!("{}.{}", name, tld);

    // run RDAP, WHOIS, and DNS all in parallel
    let rdap_fut = async {
        let Some(primary) = rdap_url(&name, tld) else {
            return Availability::Unknown;
        };
        let result = http_query(&client, &primary, &sem).await;
        match result {
            Availability::Unknown => {
                let fallback = format!("https://rdap.org/domain/{}.{}", name, tld);
                if fallback != primary { http_query(&client, &fallback, &sem).await }
                else { Availability::Unknown }
            }
            other => other,
        }
    };

    let (rdap_result, whois_result, dns_result) = tokio::join!(
        rdap_fut,
        whois_check(&name, tld),
        dns_check(&client, &name, tld)
    );

    (domain, merge_results(rdap_result, whois_result, dns_result))
}

fn date_to_epoch_days(y: i64, m: i64, d: i64) -> i64 {
    let a = (14 - m) / 12;
    let y2 = y + 4800 - a;
    let m2 = m + 12 * a - 3;
    let jdn = d + (153 * m2 + 2) / 5 + 365 * y2 + y2 / 4 - y2 / 100 + y2 / 400 - 32045;
    jdn - 2440588
}

fn days_until(date_str: &str) -> Option<i64> {
    let p: Vec<i64> = date_str.splitn(3, '-')
        .map(|s| s.parse().ok())
        .collect::<Option<Vec<_>>>()?;
    let target = date_to_epoch_days(p[0], p[1], p[2]);
    let today = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64 / 86400;
    Some(target - today)
}

fn print_result(domain: &str, availability: &Availability, pad: usize) {
    let padded = format!("{:<width$}", domain, width = pad);
    match availability {
        Availability::Available   => {
            let tld = domain.rsplit('.').next().unwrap_or("");
            let price_str = tld_price(tld)
                .map(|p| format!("  {}/yr.", p).truecolor(100, 210, 210).to_string())
                .unwrap_or_default();
            let premium_str = if is_likely_premium(domain) {
                "  ⚠ likely premium".truecolor(220, 170, 60).to_string()
            } else {
                String::new()
            };
            println!("  {}  {}{}{}", "✓".bright_green().bold(), padded.bright_white().bold(), price_str, premium_str);
        }
        Availability::Protected   => println!("  {}  {}  {}", "★".bright_yellow().bold(), padded.truecolor(60, 60, 80), "brand protected".truecolor(80, 80, 100)),
        Availability::Unknown     => println!("  {}  {}", "?".bright_yellow(), padded.truecolor(100, 100, 80)),
        Availability::Taken(dates) => {
            let mut info = String::new();
            if let Some(ref d) = dates.registered { info.push_str(&format!("  reg {}", d)); }
            if let Some(ref d) = dates.updated    { info.push_str(&format!("  upd {}", d)); }
            let exp_str = dates.expires.as_ref().map(|d| {
                let label = format!("  exp {}", d);
                match days_until(d) {
                    Some(n) if n < 90  => label.truecolor(220, 100, 60).to_string(),
                    Some(n) if n < 365 => label.truecolor(200, 170, 60).to_string(),
                    _                  => label.truecolor(110, 100, 150).to_string(),
                }
            });
            let meta = info.truecolor(110, 100, 150).to_string()
                + exp_str.as_deref().unwrap_or("");
            if dates.registered.is_none() && dates.updated.is_none() && dates.expires.is_none() {
                println!("  {}  {}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80));
            } else {
                println!("  {}  {}{}", "✗".truecolor(70, 70, 90), padded.truecolor(60, 60, 80), meta);
            }
        }
    }
}

fn generate_suggestions(keywords: &[String]) -> Vec<String> {
    let prefixes = ["get", "try", "use", "go", "my", "the", "run", "hey"];
    let suffixes = ["hq", "app", "lab", "hub", "base"];
    let mut names = Vec::new();
    for kw in keywords {
        names.push(kw.clone());
        for p in &prefixes { names.push(format!("{}{}", p, kw)); }
        for s in &suffixes { names.push(format!("{}{}", kw, s)); }
    }
    if keywords.len() >= 2 {
        names.push(keywords.join(""));
        names.push(keywords.join("-"));
    }
    let mut seen = std::collections::HashSet::new();
    names.retain(|n| seen.insert(n.clone()));
    names.truncate(14);
    names
}

fn print_help() {
    let row = |c: &str, desc: &str| {
        println!("    {}{}",
            format!("{:<20}", c).bright_white(),
            desc.truecolor(110, 110, 140)
        );
    };
    println!();
    println!("  {}", "search".truecolor(80, 80, 100));
    row("name",              "check name across all TLDs");
    row("name.tld",          "check a single domain");
    row("name+",             "suggest prefix/suffix variants");
    row("+",                 "suggest for last searched name");
    println!();
    println!("  {}", "watchlist".truecolor(80, 80, 100));
    row("/watch <domain>",   "get notified when a domain frees up");
    row("/unwatch <domain>", "stop watching");
    row("/list",             "show watchlist");
    println!();
    println!("  {}", "other".truecolor(80, 80, 100));
    row("/help",             "show this help");
    row("exit, q",           "quit (also esc)");
    println!();
}

fn print_cat() {
    println!();
    println!("{}", "   ____       _   _ ".truecolor(255, 155, 0));
    println!("{}", "  |  _ \\  ___| |_| |_".truecolor(255, 60, 90));
    println!("{}", "  | | | |/ _ \\ __| __|".truecolor(180, 50, 230));
    println!("{}", "  | |_| | (_) | |_| |_".truecolor(80, 130, 255));
    println!("{}", format!("  |____/ \\___/ \\__|\\__|  v{}", env!("CARGO_PKG_VERSION")).truecolor(50, 215, 235));
    println!();
    println!("{}", "  private domain search..".truecolor(80, 80, 110));
    println!("{}", "  type a name and hit enter. /help for commands.".truecolor(110, 105, 140));
    println!();
    println!();
}

// read a line with raw mode — handles typing, backspace, enter, esc/ctrl-c
fn read_input(prompt: &str) -> Option<String> {
    let mut buf = String::new();

    print!("{}", prompt);
    io::stdout().flush().unwrap();

    enable_raw_mode().unwrap();

    let result = loop {
        let Ok(Event::Key(key)) = event::read() else { continue };
        match key.code {
            KeyCode::Esc => break None,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break None,
            KeyCode::Enter => {
                println!();
                break Some(buf.clone());
            }
            KeyCode::Backspace => {
                if !buf.is_empty() {
                    buf.pop();
                    execute!(io::stdout(), cursor::MoveLeft(1), Clear(ClearType::UntilNewLine)).unwrap();
                }
            }
            KeyCode::Char(c) => {
                buf.push(c);
                print!("{}", c);
                io::stdout().flush().unwrap();
            }
            _ => {}
        }
    };

    disable_raw_mode().unwrap();
    result
}

async fn search_and_print(client: &Client, name: &str, tld_list: Vec<&'static str>, plain: bool, cache: Option<&Cache>) {
    let sem = Arc::new(Semaphore::new(10));
    let tasks: Vec<_> = tld_list.iter().map(|tld| {
        check_domain_cached(client.clone(), name.to_string(), tld, sem.clone(), cache.cloned())
    }).collect();

    // spinner
    let spinning = Arc::new(AtomicBool::new(true));
    let spinner_handle = if !plain {
        print!("\n");
        io::stdout().flush().unwrap();
        let spinning = spinning.clone();
        Some(tokio::spawn(async move {
            let frames = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
            let mut i = 0usize;
            while spinning.load(Ordering::Relaxed) {
                print!("\r  {}", frames[i % frames.len()].truecolor(160, 120, 220));
                io::stdout().flush().unwrap();
                i += 1;
                tokio::time::sleep(Duration::from_millis(80)).await;
            }
            print!("\r");
            execute!(io::stdout(), Clear(ClearType::CurrentLine)).unwrap();
        }))
    } else {
        None
    };

    let mut results: Vec<(String, Availability)> = join_all(tasks).await;

    // stop spinner and wait for it to clear before printing results
    if let Some(handle) = spinner_handle {
        spinning.store(false, Ordering::Relaxed);
        let _ = handle.await;
    }

    // sort and print all at once
    results.sort_by(|(da, aa), (db, ab)| {
        let is_com_a = da.ends_with(".com");
        let is_com_b = db.ends_with(".com");
        if is_com_a != is_com_b {
            return is_com_b.cmp(&is_com_a);
        }
        let status_rank = |a: &Availability| match a {
            Availability::Available  => 0u8,
            Availability::Unknown    => 1,
            Availability::Protected  => 2,
            Availability::Taken(_)   => 3,
        };
        (status_rank(aa), tld_rank(da)).cmp(&(status_rank(ab), tld_rank(db)))
    });

    if plain {
        for (domain, av) in &results {
            println!("{} {}", domain, av.as_str());
        }
        return;
    }

    let pad = results.iter().map(|(d, _)| d.len()).max().unwrap_or(0);
    for (domain, av) in &results {
        print_result(domain, av, pad);
    }

    let n = results.iter()
        .filter(|(_, a)| matches!(a, Availability::Available))
        .count();

    println!();
    println!(
        "  {} available  ·  {} checked",
        n.to_string().bright_green().bold(),
        results.len().to_string().truecolor(80, 80, 100)
    );
    println!();
}

async fn print_update(handle: tokio::task::JoinHandle<Option<String>>) {
    if let Ok(Some(version)) = handle.await {
        println!(
            "  {} {}\n",
            "update available →".truecolor(100, 95, 130),
            format!("brew upgrade dott  (v{})", version).bright_white()
        );
    }
}

fn watchlist_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".dott").join("watchlist.json")
}

fn load_watchlist() -> Vec<WatchEntry> {
    let path = watchlist_path();
    if !path.exists() { return Vec::new(); }
    serde_json::from_str(&fs::read_to_string(path).unwrap_or_default()).unwrap_or_default()
}

fn save_watchlist(entries: &[WatchEntry]) {
    let path = watchlist_path();
    if let Some(parent) = path.parent() { let _ = fs::create_dir_all(parent); }
    let _ = fs::write(path, serde_json::to_string_pretty(entries).unwrap_or_default());
}

fn send_notification(title: &str, body: &str) {
    let script = format!("display notification {} with title {}",
        serde_json::to_string(body).unwrap_or_default(),
        serde_json::to_string(title).unwrap_or_default());
    let _ = std::process::Command::new("osascript").arg("-e").arg(&script).output();
}

fn install_launch_agent() {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    let plist_path = PathBuf::from(&home).join("Library").join("LaunchAgents").join("com.dott.watch.plist");
    let binary = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("dott")).to_string_lossy().to_string();

    // if plist exists and already points to the current binary, leave it alone.
    // otherwise it's stale (binary moved, `brew upgrade`, `cargo install` from a new path) — unload and rewrite.
    if let Ok(existing) = fs::read_to_string(&plist_path) {
        if existing.contains(&binary) { return; }
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&plist_path).output();
    }

    let plist = format!(r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.dott.watch</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>--background-check</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict><key>Hour</key><integer>9</integer><key>Minute</key><integer>0</integer></dict>
</dict>
</plist>"#);
    if let Some(parent) = plist_path.parent() { let _ = fs::create_dir_all(parent); }
    if fs::write(&plist_path, plist).is_ok() {
        let _ = std::process::Command::new("launchctl").arg("load").arg(&plist_path).output();
    }
}

async fn cmd_watch(client: &Client, domain: &str) {
    if !domain.contains('.') {
        println!("\n  {} please specify a full domain, e.g. {}\n", "!".bright_yellow(), format!("dott --watch {}.com", domain).bright_white());
        return;
    }
    let domain = domain.to_lowercase();
    let mut entries = load_watchlist();
    let first_domain = entries.is_empty();

    if entries.iter().any(|e| e.domain == domain) {
        println!("\n  {} {} is already being watched\n", "·".truecolor(100, 100, 120), domain.bright_white());
        return;
    }

    let parts: Vec<&str> = domain.rsplitn(2, '.').collect();
    let tld_str = if parts.len() == 2 { parts[0] } else { "com" };
    let name_str = if parts.len() == 2 { parts[1] } else { domain.as_str() };
    let tld: &'static str = ALL_TLDS.iter().find(|&&t| t == tld_str).copied().unwrap_or("com");
    let (_, status) = check_domain(client.clone(), name_str.to_string(), tld, Arc::new(Semaphore::new(1))).await;
    let status_str = status.as_str().to_string();

    entries.push(WatchEntry { domain: domain.clone(), last_status: status_str.clone() });
    save_watchlist(&entries);
    install_launch_agent();

    println!("\n  {} watching {}", "✓".bright_green().bold(), domain.bright_white().bold());
    if status_str == "available" {
        println!("  {} it's available right now — go register it!", "·".bright_green());
    } else {
        println!("  {} {}", "·".truecolor(80, 80, 100), "you'll get a notification when it becomes available".truecolor(100, 100, 130));
    }

    if first_domain {
        send_notification("dott", &format!("Now watching {} — you'll be notified when it's available.", domain));
        println!("  {} {}", "·".truecolor(80, 80, 100), "test notification sent — if you didn't see it, allow notifications for Script Editor in:".truecolor(100, 100, 130));
        println!("  {}  {}", " ", "System Settings → Notifications → Script Editor".bright_white());
        let _ = std::process::Command::new("open")
            .arg("x-apple.systempreferences:com.apple.preference.notifications")
            .output();
    }
    println!();
}

async fn cmd_unwatch(domain: &str) {
    let domain = domain.to_lowercase();
    let mut entries = load_watchlist();
    let before = entries.len();
    entries.retain(|e| e.domain != domain);
    if entries.len() == before {
        println!("\n  {} {} not in watchlist\n", "·".truecolor(100, 100, 120), domain);
        return;
    }
    save_watchlist(&entries);
    println!("\n  {} stopped watching {}\n", "✓".bright_green().bold(), domain.bright_white().bold());
}

fn cmd_watching_list() {
    let entries = load_watchlist();
    println!();
    if entries.is_empty() {
        println!("  {} no domains being watched", "·".truecolor(100, 100, 120));
        println!("  {} use {} to start\n", "·".truecolor(80, 80, 100), "dott --watch <domain>".bright_white());
        return;
    }
    println!("  {}\n", "watching:".truecolor(80, 80, 100));
    for e in &entries {
        let status_colored = match e.last_status.as_str() {
            "available"  => e.last_status.bright_green().to_string(),
            "taken"      => e.last_status.truecolor(60, 60, 80).to_string(),
            "protected"  => e.last_status.bright_yellow().to_string(),
            _            => e.last_status.truecolor(100, 100, 80).to_string(),
        };
        println!("  {}  {}  {}", "·".truecolor(100, 100, 120), e.domain.bright_white(), status_colored);
    }
    println!();
}

async fn cmd_background_check(client: &Client) {
    let mut entries = load_watchlist();
    if entries.is_empty() { return; }
    let sem = Arc::new(Semaphore::new(5));
    let domains: Vec<(String, &'static str)> = entries.iter().map(|e| {
        let parts: Vec<&str> = e.domain.rsplitn(2, '.').collect();
        let tld_str = if parts.len() == 2 { parts[0] } else { "com" };
        let name = if parts.len() == 2 { parts[1] } else { e.domain.as_str() };
        let tld = ALL_TLDS.iter().find(|&&t| t == tld_str).copied().unwrap_or("com");
        (name.to_string(), tld)
    }).collect();
    let tasks: Vec<_> = domains.iter().map(|(name, tld)| {
        check_domain(client.clone(), name.clone(), tld, sem.clone())
    }).collect();
    let results = join_all(tasks).await;
    let mut changed = false;
    for (entry, (_, status)) in entries.iter_mut().zip(results.iter()) {
        let new_status = status.as_str();
        if new_status != entry.last_status {
            if new_status == "available" {
                send_notification("dott — available!", &format!("{} is now available to register!", entry.domain));
            }
            entry.last_status = new_status.to_string();
            changed = true;
        }
    }
    if changed { save_watchlist(&entries); }
}

async fn check_for_update(client: Client) -> Option<String> {
    let res = client
        .get("https://api.github.com/repos/yodatoshicom/dott/releases/latest")
        .header("User-Agent", "dott")
        .timeout(Duration::from_secs(3))
        .send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    let latest = json["tag_name"].as_str()?.trim_start_matches('v').to_string();
    let current = env!("CARGO_PKG_VERSION");
    let parse_ver = |s: &str| -> Option<(u32, u32, u32)> {
        let mut parts = s.split('.');
        Some((parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?))
    };
    if parse_ver(&latest)? > parse_ver(current)? { Some(latest) } else { None }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let client = Client::new();

    if cli.background_check { cmd_background_check(&client).await; return; }
    if let Some(ref domain) = cli.watch    { cmd_watch(&client, domain).await; return; }
    if let Some(ref domain) = cli.unwatch  { cmd_unwatch(domain).await; return; }
    if cli.watching { cmd_watching_list(); return; }

    // ── pipe mode: read names from stdin, always plain output ──
    if cli.name.is_none() && cli.suggest.is_none() && !io::stdin().is_terminal() {
        let default_tlds: Vec<&'static str> = if let Some(ref t) = cli.tlds {
            t.split(',').filter_map(|s| ALL_TLDS.iter().find(|&&x| x == s.trim()).copied()).collect()
        } else {
            ALL_TLDS.to_vec()
        };
        for line in io::stdin().lock().lines() {
            let Ok(line) = line else { continue };
            let line = line.trim();
            if line.is_empty() { continue; }
            let (name, tlds) = if let Some(dot) = line.rfind('.') {
                let tld_str = &line[dot+1..];
                match ALL_TLDS.iter().find(|&&t| t == tld_str).copied() {
                    Some(tld) => (line[..dot].to_string(), vec![tld]),
                    None => continue,
                }
            } else {
                (line.to_string(), default_tlds.clone())
            };
            search_and_print(&client, &name, tlds, true, None).await;
        }
        return;
    }

    let update_check = tokio::spawn(check_for_update(client.clone()));

    // ── one-shot mode ──────────────────────────────────────────
    if let Some(keywords) = cli.suggest {
        println!();
        println!("{}", "  · d o t t ·".bright_magenta().bold());
        println!();
        println!("  {} {}\n", "generating for:".truecolor(80, 80, 100), keywords.join(", ").bright_white());
        let suggestions = generate_suggestions(&keywords);
        let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
        let sem = Arc::new(Semaphore::new(10));
        let tasks: Vec<_> = suggestions.iter().flat_map(|name| {
            let name = name.clone(); let client = client.clone(); let sem = sem.clone();
            tlds.iter().map(move |tld| check_domain(client.clone(), name.clone(), tld, sem.clone()))
        }).collect();
        let results = join_all(tasks).await;
        let available: Vec<&str> = results.iter()
            .filter(|(_, a)| matches!(a, Availability::Available))
            .map(|(d, _)| d.as_str()).collect();
        if cli.plain {
            for (domain, av) in &results {
                println!("{} {}", domain, av.as_str());
            }
        } else if available.is_empty() {
            println!("  {} nothing available\n", "✗".truecolor(80, 80, 100));
        } else {
            for d in &available { println!("  {}  {}", "✓".bright_green().bold(), d.bright_white().bold()); }
            println!("\n  {} available\n", available.len().to_string().bright_green().bold());
        }
        print_update(update_check).await;
        return;
    }

    if let Some(raw) = cli.name {
        println!();
        println!("{}", "  · d o t t ·".bright_magenta().bold());
        println!();
        let name = if let Some(dot) = raw.find('.') { raw[..dot].to_string() } else { raw };
        let tld_list: Vec<&'static str> = if let Some(ref t) = cli.tlds {
            t.split(',').filter_map(|s| ALL_TLDS.iter().find(|&&x| x == s.trim()).copied()).collect()
        } else {
            ALL_TLDS.to_vec()
        };
        if !cli.plain { println!("  {} {}", "checking:".truecolor(80, 80, 100), name.bright_white()); }
        search_and_print(&client, &name, tld_list, cli.plain, None).await;
        print_update(update_check).await;
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();

    let cache = new_cache();
    let mut last_name: Option<String> = None;

    loop {
        let prompt = format!("  {} ", "›".bright_magenta().bold());
        match read_input(&prompt) {
            None => {
                println!("\n  {}\n", "bye 🐱".truecolor(180, 140, 200));
                print_update(update_check).await;
                break;
            }
            Some(input) => {
                let input = input.trim().to_string();
                if input.is_empty() { continue; }
                if input == "exit" || input == "quit" || input == "q" {
                    println!("\n  {}\n", "bye 🐱".truecolor(180, 140, 200));
                    print_update(update_check).await;
                    break;
                }

                // 'name+' → suggest ; bare '+' reuses the last searched name
                if let Some(raw) = input.strip_suffix('+') {
                    let name = if raw.is_empty() {
                        match last_name.clone() {
                            Some(n) => n,
                            None => {
                                println!("  {}\n", "search for a name first".truecolor(100, 100, 120));
                                continue;
                            }
                        }
                    } else if let Some(dot) = raw.find('.') {
                        raw[..dot].to_string()
                    } else {
                        raw.to_string()
                    };
                    println!("  {} {}", "suggesting for:".truecolor(80, 80, 100), name.bright_white());
                    let suggestions = generate_suggestions(&[name.clone()]);
                    let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
                    let sem = Arc::new(Semaphore::new(10));
                    let tasks: Vec<_> = suggestions.iter().flat_map(|n| {
                        let n = n.clone();
                        let client = client.clone();
                        let sem = sem.clone();
                        let cache = cache.clone();
                        tlds.iter().map(move |tld| check_domain_cached(client.clone(), n.clone(), tld, sem.clone(), Some(cache.clone())))
                    }).collect();
                    let results = join_all(tasks).await;
                    let available: Vec<&str> = results.iter()
                        .filter(|(_, a)| matches!(a, Availability::Available))
                        .map(|(d, _)| d.as_str())
                        .collect();
                    println!();
                    if available.is_empty() {
                        println!("  {}  nothing available\n", "✗".truecolor(80, 80, 100));
                    } else {
                        for d in &available {
                            println!("  {}  {}", "✓".bright_green().bold(), d.bright_white().bold());
                        }
                        println!();
                        println!("  {} available\n", available.len().to_string().bright_green().bold());
                    }
                    continue;
                }

                // /watch <domain>, /unwatch <domain>, /list
                if let Some(domain) = input.strip_prefix("/watch ") {
                    cmd_watch(&client, domain.trim()).await;
                    continue;
                }
                if let Some(domain) = input.strip_prefix("/unwatch ") {
                    cmd_unwatch(domain.trim()).await;
                    continue;
                }
                if input == "/list" {
                    cmd_watching_list();
                    continue;
                }
                if input == "/help" {
                    print_help();
                    continue;
                }

                // strip TLD if included
                let name = if let Some(dot) = input.find('.') {
                    input[..dot].to_string()
                } else {
                    input
                };
                println!("  {} {}", "checking:".truecolor(80, 80, 100), name.bright_white());
                search_and_print(&client, &name, ALL_TLDS.to_vec(), false, Some(&cache)).await;
                last_name = Some(name);

                println!();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_date_iso() {
        assert_eq!(parse_date("2026-04-19"), Some("2026-04-19".to_string()));
    }

    #[test]
    fn parse_date_embedded_in_timestamp() {
        assert_eq!(parse_date("Expires: 2027-01-15T00:00:00Z"), Some("2027-01-15".to_string()));
    }

    #[test]
    fn parse_date_returns_first_match() {
        assert_eq!(parse_date("reg 2020-01-01 exp 2030-12-31"), Some("2020-01-01".to_string()));
    }

    #[test]
    fn parse_date_none() {
        assert_eq!(parse_date("no dates here"), None);
        assert_eq!(parse_date(""), None);
        assert_eq!(parse_date("2026-1-1"), None); // non-zero-padded rejected
    }

    fn dates_with_expiry(exp: &str) -> DomainDates {
        DomainDates { registered: None, updated: None, expires: Some(exp.to_string()) }
    }

    #[test]
    fn dns_taken_overrides_all_unknown() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Unknown,
            Availability::Taken(DomainDates::default()),
        );
        assert!(matches!(out, Availability::Taken(_)));
    }

    #[test]
    fn dns_taken_keeps_whois_expiry() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Taken(DomainDates::default()),
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken with WHOIS expiry preserved"),
        }
    }

    #[test]
    fn rdap_wins_but_whois_fills_gaps() {
        let rdap = DomainDates {
            registered: Some("2020-01-01".into()),
            updated:    None,
            expires:    Some("2026-01-01".into()),
        };
        let whois = DomainDates {
            registered: Some("2019-05-05".into()),
            updated:    Some("2024-06-06".into()),
            expires:    Some("2027-12-31".into()),
        };
        let out = merge_results(
            Availability::Taken(rdap),
            Availability::Taken(whois),
            Availability::Unknown,
        );
        match out {
            Availability::Taken(d) => {
                assert_eq!(d.registered.as_deref(), Some("2020-01-01")); // RDAP wins
                assert_eq!(d.updated.as_deref(),    Some("2024-06-06")); // WHOIS fills gap
                assert_eq!(d.expires.as_deref(),    Some("2026-01-01")); // RDAP wins
            }
            _ => panic!("expected Taken"),
        }
    }

    #[test]
    fn rdap_available_beats_everything() {
        let out = merge_results(
            Availability::Available,
            Availability::Taken(DomainDates::default()),
            Availability::Unknown,
        );
        assert!(matches!(out, Availability::Available));
    }

    #[test]
    fn whois_fallback_when_rdap_unknown() {
        let out = merge_results(
            Availability::Unknown,
            Availability::Taken(dates_with_expiry("2027-01-01")),
            Availability::Unknown,
        );
        match out {
            Availability::Taken(d) => assert_eq!(d.expires.as_deref(), Some("2027-01-01")),
            _ => panic!("expected Taken from WHOIS fallback"),
        }
    }

    #[test]
    fn premium_heuristic_flags_short_names_in_premium_tlds() {
        assert!(is_likely_premium("go.ai"));
        assert!(is_likely_premium("x.io"));
        assert!(is_likely_premium("app.dev"));
        assert!(is_likely_premium("four.co"));
    }

    #[test]
    fn premium_heuristic_ignores_long_names_and_other_tlds() {
        assert!(!is_likely_premium("mystartup.ai"));   // too long
        assert!(!is_likely_premium("go.com"));          // not a flagged TLD
        assert!(!is_likely_premium("go.xyz"));          // not a flagged TLD
        assert!(!is_likely_premium("noseparator"));     // no TLD
    }

    #[test]
    fn all_unknown_stays_unknown() {
        let out = merge_results(Availability::Unknown, Availability::Unknown, Availability::Unknown);
        assert!(matches!(out, Availability::Unknown));
    }
}
