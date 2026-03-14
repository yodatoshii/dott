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
use std::{io::{self, Write}, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[derive(Parser)]
#[command(name = "dott", about = "private domain search. no middlemen.")]
struct Cli {
    name: Option<String>,
    #[arg(short, long)]
    tlds: Option<String>,
    #[arg(short, long, num_args = 1..)]
    suggest: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
enum Availability {
    Available,
    Taken,
    Unknown,
}

const ALL_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me",
    "sh", "gg", "cc", "cv", "xyz",
];

fn rdap_url(name: &str, tld: &str) -> String {
    match tld {
        "com"      => format!("https://rdap.verisign.com/com/v1/domain/{}.{}", name, tld),
        "net"      => format!("https://rdap.verisign.com/net/v1/domain/{}.{}", name, tld),
        "org"      => format!("https://rdap.publicinterestregistry.org/rdap/domain/{}.{}", name, tld),
        "io"       => format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld),
        "dev"      => format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld),
        "app"      => format!("https://pubapi.registry.google/rdap/domain/{}.{}", name, tld),
        "ai"       => format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld),
        "me"       => format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld),
        "sh"       => format!("https://rdap.identitydigital.services/rdap/domain/{}.{}", name, tld),
        "cc"       => format!("https://tld-rdap.verisign.com/cc/v1/domain/{}.{}", name, tld),
        "xyz"      => format!("https://rdap.centralnic.com/xyz/domain/{}.{}", name, tld),
        "cv"       => format!("https://rdap.nic.cv/domain/{}.{}", name, tld),
        _          => format!("https://rdap.org/domain/{}.{}", name, tld),
    }
}

fn whois_server(tld: &str) -> Option<&'static str> {
    match tld {
        // only list servers confirmed working — dead servers cause 4s timeouts
        "cc"       => Some("whois.nic.cc"),
        "xyz"      => Some("whois.nic.xyz"),
        "gg"       => Some("whois.gg"),
        "com"      => Some("whois.verisign-grs.com"),
        "net"      => Some("whois.verisign-grs.com"),
        "org"      => Some("whois.pir.org"),
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

    let mut stream = match tokio::time::timeout(
        Duration::from_secs(4),
        TcpStream::connect(&addr),
    ).await {
        Ok(Ok(s)) => s,
        _         => return Availability::Unknown,
    };

    if stream.write_all(query.as_bytes()).await.is_err() {
        return Availability::Unknown;
    }

    let mut response = String::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(4),
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
        Availability::Taken
    } else {
        Availability::Unknown
    }
}

async fn dns_check(name: &str, tld: &str) -> Availability {
    let domain = format!("{}.{}:80", name, tld);
    let found = tokio::task::spawn_blocking(move || {
        use std::net::ToSocketAddrs;
        domain.to_socket_addrs().is_ok()
    }).await.unwrap_or(false);
    if found { Availability::Taken } else { Availability::Unknown }
}

async fn http_query(client: &Client, url: &str) -> Availability {
    match client.get(url).timeout(Duration::from_secs(5)).send().await {
        Ok(resp) => match resp.status().as_u16() {
            404 => Availability::Available,
            200 => Availability::Taken,
            _   => Availability::Unknown,
        },
        Err(_) => Availability::Unknown,
    }
}

async fn check_domain(client: Client, name: String, tld: &'static str) -> (String, Availability) {
    let domain = format!("{}.{}", name, tld);

    // run RDAP and WHOIS in parallel
    let rdap_fut = async {
        let primary = rdap_url(&name, tld);
        let result = http_query(&client, &primary).await;
        match result {
            Availability::Unknown => {
                let fallback = format!("https://rdap.org/domain/{}.{}", name, tld);
                if fallback != primary { http_query(&client, &fallback).await }
                else { Availability::Unknown }
            }
            other => other,
        }
    };

    let (rdap_result, whois_result) = tokio::join!(rdap_fut, whois_check(&name, tld));

    let result = match rdap_result {
        Availability::Unknown => whois_result,
        other => other,
    };

    let result = match result {
        Availability::Unknown => dns_check(&name, tld).await,
        other => other,
    };

    (domain, result)
}

fn print_result(domain: &str, availability: &Availability) {
    match availability {
        Availability::Available => println!("  {}  {}", "✓".bright_green().bold(), domain.bright_white().bold()),
        Availability::Taken     => println!("  {}  {}", "✗".truecolor(70, 70, 90), domain.truecolor(60, 60, 80)),
        Availability::Unknown   => println!("  {}  {}", "?".bright_yellow(), domain.truecolor(100, 100, 80)),
    }
}

fn generate_suggestions(keywords: &[String]) -> Vec<String> {
    let prefixes = ["get", "try", "use", "go", "my", "the", "run", "hey"];
    let suffixes = ["hq", "app", "cli", "lab", "hub", "kit", "base", "dot"];
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
    println!("{}", "  |____/ \\___/ \\__|\\__|  v1.0".truecolor(50, 215, 235));
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

async fn search_and_print(name: &str, tld_list: Vec<&'static str>) {
    println!();
    let total = tld_list.len();
    let (tx, mut rx) = mpsc::unbounded_channel::<(String, Availability)>();
    let client = Client::new();

    // spawn all checks, each sends result as soon as it's done
    for tld in tld_list {
        let tx     = tx.clone();
        let client = client.clone();
        let name   = name.to_string();
        tokio::spawn(async move {
            let result = check_domain(client, name, tld).await;
            let _ = tx.send(result);
        });
    }
    drop(tx);

    let mut received = 0;
    let mut results: Vec<(String, Availability)> = Vec::new();

    while received < total {
        if let Some(r) = rx.recv().await {
            results.push(r);
            received += 1;
        }
    }

    // sort and print all at once
    results.sort_by_key(|(_, a)| match a {
        Availability::Available => 0,
        Availability::Unknown   => 1,
        Availability::Taken     => 2,
    });

    for (domain, av) in &results {
        print_result(domain, av);
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
        .get("https://api.github.com/repos/yodatoshii/dott/releases/latest")
        .header("User-Agent", "dott")
        .timeout(Duration::from_secs(3))
        .send().await.ok()?;
    let json: serde_json::Value = res.json().await.ok()?;
    let latest = json["tag_name"].as_str()?.trim_start_matches('v').to_string();
    let current = env!("CARGO_PKG_VERSION");
    if latest != current { Some(latest) } else { None }
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
        let tasks: Vec<_> = suggestions.iter().flat_map(|name| {
            let name = name.clone(); let client = client.clone();
            tlds.iter().map(move |tld| check_domain(client.clone(), name.clone(), tld))
        }).collect();
        let results = join_all(tasks).await;
        let available: Vec<&str> = results.iter()
            .filter(|(_, a)| matches!(a, Availability::Available))
            .map(|(d, _)| d.as_str()).collect();
        if available.is_empty() {
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
        println!("  {} {}", "checking:".truecolor(80, 80, 100), name.bright_white());
        search_and_print(&name, tld_list).await;
        print_update(update_check).await;
        return;
    }

    // ── interactive mode ───────────────────────────────────────
    print_cat();

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
                    break;
                }
                // strip TLD if included
                let name = if let Some(dot) = input.find('.') {
                    input[..dot].to_string()
                } else {
                    input
                };
                println!("  {} {}", "checking:".truecolor(80, 80, 100), name.bright_white());
                search_and_print(&name, ALL_TLDS.to_vec()).await;
                println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
                println!(
                    "  {}  {}    {}  {}    {}  {}    {}  {}",
                    "✓".bright_green(),        "available".truecolor(70, 70, 90),
                    "?".bright_yellow(),       "unknown".truecolor(70, 70, 90),
                    "✗".truecolor(70, 70, 90), "taken".truecolor(70, 70, 90),
                    "ctrl+c".truecolor(100, 95, 130), "quit".truecolor(70, 70, 90),
                );
                println!("{}", "  ─────────────────────────────────────────────────────".truecolor(38, 36, 52));
            }
        }
    }
}
