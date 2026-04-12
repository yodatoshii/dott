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
use std::{io::{self, Write}, sync::atomic::{AtomicBool, Ordering}, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Semaphore};
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

    // merge two DomainDates, preferring non-None fields
    let merge_dates = |a: DomainDates, b: DomainDates| -> DomainDates {
        DomainDates {
            registered: a.registered.or(b.registered),
            updated:    a.updated.or(b.updated),
            expires:    a.expires.or(b.expires),
        }
    };

    // DNS confirming active = definitely taken; merge dates from RDAP + WHOIS
    if matches!(dns_result, Availability::Taken(_)) {
        let dates = match (rdap_result, whois_result) {
            (Availability::Taken(a), Availability::Taken(b)) => merge_dates(a, b),
            (Availability::Taken(a), _) => a,
            (_, Availability::Taken(b)) => b,
            _ => DomainDates::default(),
        };
        return (domain, Availability::Taken(dates));
    }

    // merge RDAP and WHOIS dates when both are Taken
    let result = match (rdap_result, whois_result) {
        (Availability::Unknown, whois)                      => whois,
        (Availability::Taken(a), Availability::Taken(b))   => Availability::Taken(merge_dates(a, b)),
        (rdap, _)                                           => rdap,
    };

    let result = match result {
        Availability::Unknown => dns_result,
        other => other,
    };

    (domain, result)
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
        Availability::Available   => println!("  {}  {}", "✓".bright_green().bold(), padded.bright_white().bold()),
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
    names.dedup();
    names.truncate(14);
    names
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
    println!("{}", "  type a name and hit enter. esc to quit.".truecolor(110, 105, 140));
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
        if event::poll(Duration::from_millis(100)).unwrap() {
            if let Event::Key(key) = event::read().unwrap() {
                match key.code {
                    KeyCode::Esc => {
                        break None;
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break None;
                    }
                    KeyCode::Enter => {
                        println!();
                        break Some(buf.clone());
                    }
                    KeyCode::Backspace => {
                        if !buf.is_empty() {
                            buf.pop();
                            execute!(
                                io::stdout(),
                                cursor::MoveLeft(1),
                                Clear(ClearType::UntilNewLine)
                            ).unwrap();
                        }
                    }
                    KeyCode::Char(c) => {
                        buf.push(c);
                        print!("{}", c);
                        io::stdout().flush().unwrap();
                    }
                    _ => {}
                }
            }
        }
    };

    disable_raw_mode().unwrap();
    result
}

async fn search_and_print(name: &str, tld_list: Vec<&'static str>, plain: bool) {
    let total = tld_list.len();
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, Availability)>();
    let client = Client::new();
    let sem = Arc::new(Semaphore::new(10));

    // spawn all checks, each sends result as soon as it's done
    for tld in tld_list {
        let tx     = tx.clone();
        let client = client.clone();
        let name   = name.to_string();
        let sem    = sem.clone();
        tokio::spawn(async move {
            let result = check_domain(client, name, tld, sem).await;
            let _ = tx.send(result);
        });
    }
    drop(tx);

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

    let mut received = 0;
    let mut results: Vec<(String, Availability)> = Vec::new();

    while received < total {
        if let Some(r) = rx.recv().await {
            results.push(r);
            received += 1;
        }
    }

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
            let status = match av {
                Availability::Available => "available",
                Availability::Taken(_)  => "taken",
                Availability::Protected => "protected",
                Availability::Unknown   => "unknown",
            };
            println!("{} {}", domain, status);
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

async fn check_for_update() -> Option<String> {
    let client = Client::new();
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
    let update_check = tokio::spawn(check_for_update());

    // ── one-shot mode ──────────────────────────────────────────
    if let Some(keywords) = cli.suggest {
        println!();
        println!("{}", "  · d o t t ·".bright_magenta().bold());
        println!();
        println!("  {} {}\n", "generating for:".truecolor(80, 80, 100), keywords.join(", ").bright_white());
        let suggestions = generate_suggestions(&keywords);
        let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
        let client = Client::new();
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
                let status = match av {
                    Availability::Available => "available",
                    Availability::Taken(_)  => "taken",
                    Availability::Protected => "protected",
                    Availability::Unknown   => "unknown",
                };
                println!("{} {}", domain, status);
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
        search_and_print(&name, tld_list, cli.plain).await;
        print_update(update_check).await;
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();

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

                // 's' → suggest for last searched name
                if input == "s" {
                    if let Some(ref name) = last_name {
                        println!("  {} {}", "suggesting for:".truecolor(80, 80, 100), name.bright_white());
                        let suggestions = generate_suggestions(&[name.clone()]);
                        let tlds: Vec<&'static str> = vec!["com", "io", "dev", "app", "co"];
                        let client = Client::new();
                        let sem = Arc::new(Semaphore::new(10));
                        let tasks: Vec<_> = suggestions.iter().flat_map(|n| {
                            let n = n.clone();
                            let client = client.clone();
                            let sem = sem.clone();
                            tlds.iter().map(move |tld| check_domain(client.clone(), n.clone(), tld, sem.clone()))
                        }).collect();
                        let mut results = join_all(tasks).await;
                        results.sort_by_key(|(_, a)| match a {
                            Availability::Available => 0,
                            Availability::Unknown   => 1,
                            Availability::Protected => 2,
                            Availability::Taken(_)  => 3,
                        });
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
                    } else {
                        println!("  {}\n", "search for a name first".truecolor(100, 100, 120));
                    }
                    continue;
                }

                // strip TLD if included
                let name = if let Some(dot) = input.find('.') {
                    input[..dot].to_string()
                } else {
                    input
                };
                println!("  {} {}", "checking:".truecolor(80, 80, 100), name.bright_white());
                search_and_print(&name, ALL_TLDS.to_vec(), false).await;
                last_name = Some(name);

                println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
                println!(
                    "  {}  {}    {}  {}    {}  {}    {}  {}    {}  {}",
                    "✓".bright_green(),        "available".truecolor(70, 70, 90),
                    "?".bright_yellow(),       "unknown".truecolor(70, 70, 90),
                    "✗".truecolor(70, 70, 90), "taken".truecolor(70, 70, 90),
                    "s".truecolor(160, 120, 220),      "suggest".truecolor(70, 70, 90),
                    "ctrl+c".truecolor(100, 95, 130),  "quit".truecolor(70, 70, 90),
                );
                println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
            }
        }
    }
}
