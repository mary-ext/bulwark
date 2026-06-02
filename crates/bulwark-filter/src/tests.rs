use std::net::{IpAddr, Ipv4Addr};

use crate::rule::*;
use crate::*;

fn ci<'a>() -> ClientInfo<'a> {
    ClientInfo::default()
}

#[test]
fn blocks_domain_and_subdomains() {
    let e = compile_one("||ads.example.com^");
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("a.b.ads.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("notads.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("example.com", "A", &ci()).is_blocked());
}

#[test]
fn bare_domain_treated_as_subdomain_block() {
    let e = compile_one("doubleclick.net");
    assert!(e.check("doubleclick.net", "A", &ci()).is_blocked());
    assert!(e.check("ad.doubleclick.net", "A", &ci()).is_blocked());
}

#[test]
fn exception_unblocks() {
    let e = compile_one("||example.com^\n@@||good.example.com^");
    assert!(e.check("bad.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("good.example.com", "A", &ci()).is_blocked());
    // exception applies to subdomains of the exception too
    assert!(!e.check("x.good.example.com", "A", &ci()).is_blocked());
}

#[test]
fn important_beats_exception() {
    let e = compile_one("@@||example.com^\n||tracker.example.com^$important");
    // exception covers everything, but the important block wins on the subdomain
    assert!(e.check("tracker.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("other.example.com", "A", &ci()).is_blocked());
}

#[test]
fn badfilter_disables_rule() {
    let e = compile_one("||example.com^\n||example.com^$badfilter");
    assert!(!e.check("example.com", "A", &ci()).is_blocked());
}

#[test]
fn badfilter_only_disables_matching_signature() {
    let e = compile_one("||a.com^\n||b.com^\n||a.com^$badfilter");
    assert!(!e.check("a.com", "A", &ci()).is_blocked());
    assert!(e.check("b.com", "A", &ci()).is_blocked());
}

#[test]
fn hosts_format_blocking() {
    let text = "0.0.0.0 ads.example.com\n127.0.0.1 tracker.test\n# comment\n";
    let e = compile_one(text);
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("tracker.test", "A", &ci()).is_blocked());
    // hosts entries are exact: subdomains are not blocked
    assert!(!e.check("sub.ads.example.com", "A", &ci()).is_blocked());
}

#[test]
fn hosts_noise_and_localhost_skipped() {
    let e = compile_one("127.0.0.1 localhost\n::1 ip6-localhost\n");
    assert!(matches!(
        e.check("localhost", "A", &ci()),
        Verdict::Allow { .. }
    ));
    assert!(e.is_empty());
}

#[test]
fn hosts_rewrite_to_ip() {
    let e = compile_one("192.168.1.5 router.lan");
    match e.check("router.lan", "A", &ci()) {
        Verdict::Rewrite { data, .. } => {
            assert_eq!(data, RewriteData::A(Ipv4Addr::new(192, 168, 1, 5)));
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn dnstype_modifier() {
    let e = compile_one("||example.com^$dnstype=AAAA");
    assert!(!e.check("example.com", "A", &ci()).is_blocked());
    assert!(e.check("example.com", "AAAA", &ci()).is_blocked());
}

#[test]
fn dnstype_negation() {
    let e = compile_one("||example.com^$dnstype=~A");
    assert!(!e.check("example.com", "A", &ci()).is_blocked());
    assert!(e.check("example.com", "AAAA", &ci()).is_blocked());
}

#[test]
fn dnsrewrite_short_ip() {
    let e = compile_one("||example.com^$dnsrewrite=1.2.3.4");
    match e.check("example.com", "A", &ci()) {
        Verdict::Rewrite { data, .. } => {
            assert_eq!(data, RewriteData::A(Ipv4Addr::new(1, 2, 3, 4)))
        }
        other => panic!("expected rewrite, got {other:?}"),
    }
}

#[test]
fn dnsrewrite_full_form_and_rcodes() {
    let e = compile_one(
        "||a.com^$dnsrewrite=NOERROR;A;9.9.9.9\n||b.com^$dnsrewrite=NXDOMAIN\n||c.com^$dnsrewrite=REFUSED",
    );
    assert!(matches!(
        e.check("a.com", "A", &ci()),
        Verdict::Rewrite {
            data: RewriteData::A(_),
            ..
        }
    ));
    assert!(matches!(
        e.check("b.com", "A", &ci()),
        Verdict::Rewrite {
            data: RewriteData::Rcode(RewriteRcode::NxDomain),
            ..
        }
    ));
    assert!(matches!(
        e.check("c.com", "A", &ci()),
        Verdict::Rewrite {
            data: RewriteData::Rcode(RewriteRcode::Refused),
            ..
        }
    ));
}

#[test]
fn dnsrewrite_txt_mx_ptr() {
    let e = compile_one(
        "||a.com^$dnsrewrite=NOERROR;TXT;hello world\n\
         ||b.com^$dnsrewrite=NOERROR;MX;10 mail.b.com\n\
         ||c.com^$dnsrewrite=NOERROR;PTR;host.c.com",
    );
    assert!(matches!(
        e.check("a.com", "TXT", &ci()),
        Verdict::Rewrite { data: RewriteData::Txt(t), .. } if t == "hello world"
    ));
    assert!(matches!(
        e.check("b.com", "MX", &ci()),
        Verdict::Rewrite {
            data: RewriteData::Mx { preference: 10, .. },
            ..
        }
    ));
    assert!(matches!(
        e.check("c.com", "PTR", &ci()),
        Verdict::Rewrite {
            data: RewriteData::Ptr(_),
            ..
        }
    ));
}

#[test]
fn client_modifier_by_ip() {
    let e = compile_one("||example.com^$client=10.0.0.5");
    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    let other: IpAddr = "10.0.0.6".parse().unwrap();
    let c1 = ClientInfo {
        ip: Some(ip),
        ..Default::default()
    };
    let c2 = ClientInfo {
        ip: Some(other),
        ..Default::default()
    };
    assert!(e.check("example.com", "A", &c1).is_blocked());
    assert!(!e.check("example.com", "A", &c2).is_blocked());
}

#[test]
fn client_modifier_by_cidr_and_name() {
    let e = compile_one("||example.com^$client=10.0.0.0/24|laptop");
    let in_net = ClientInfo {
        ip: Some("10.0.0.99".parse().unwrap()),
        ..Default::default()
    };
    let by_name = ClientInfo {
        name: Some("laptop"),
        ..Default::default()
    };
    let neither = ClientInfo {
        ip: Some("192.168.0.1".parse().unwrap()),
        name: Some("phone"),
        ..Default::default()
    };
    assert!(e.check("example.com", "A", &in_net).is_blocked());
    assert!(e.check("example.com", "A", &by_name).is_blocked());
    assert!(!e.check("example.com", "A", &neither).is_blocked());
}

#[test]
fn ctag_modifier() {
    let e = compile_one("||example.com^$ctag=device_kids");
    let tags = vec!["device_kids".to_string()];
    let kid = ClientInfo {
        tags: &tags,
        ..Default::default()
    };
    let adult = ClientInfo::default();
    assert!(e.check("example.com", "A", &kid).is_blocked());
    assert!(!e.check("example.com", "A", &adult).is_blocked());
}

#[test]
fn denyallow_excludes_domains() {
    let e = compile_one("||example.com^$denyallow=good.example.com");
    assert!(e.check("bad.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("good.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("x.good.example.com", "A", &ci()).is_blocked());
}

#[test]
fn wildcard_rule() {
    let e = compile_one("||*.doubleclick.net^");
    assert!(e.check("ad.doubleclick.net", "A", &ci()).is_blocked());
}

#[test]
fn regex_rule() {
    let e = compile_one(r"/^ads?\d*\./");
    assert!(e.check("ads123.example.com", "A", &ci()).is_blocked());
    assert!(e.check("ad.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("banner.example.com", "A", &ci()).is_blocked());
}

#[test]
fn comments_and_blank_lines_ignored() {
    let e = compile_one("! a comment\n\n# another\n[Adblock Plus 2.0]\n||x.com^");
    assert_eq!(e.len(), 1);
}

#[test]
fn unsupported_http_modifier_skipped() {
    // $third-party is HTTP-only; the rule must not be loaded.
    let mut c = Compiler::new();
    let stats = c.add_list(0, "t", "||example.com^$third-party");
    assert_eq!(stats.rules, 0);
    assert_eq!(stats.unsupported, 1);
}

#[test]
fn case_insensitive_and_trailing_dot() {
    let e = compile_one("||Example.COM^");
    assert!(e.check("WWW.example.com.", "A", &ci()).is_blocked());
}

#[test]
fn multi_list_stats_and_priority() {
    let mut c = Compiler::new();
    c.add_list(1, "block", "||example.com^");
    c.add_list(2, "allow", "@@||shop.example.com^");
    let (engine, stats) = c.build();
    assert_eq!(stats.len(), 2);
    assert!(engine.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(!engine.check("shop.example.com", "A", &ci()).is_blocked());
}

#[test]
fn duplicate_rules_are_deduplicated() {
    // The same domain across several lists should collapse to one rule.
    let mut c = Compiler::new();
    c.add_list(1, "a", "||ads.example.com^\n0.0.0.0 dup.test");
    c.add_list(2, "b", "||ads.example.com^\n0.0.0.0 dup.test");
    c.add_list(3, "c", "||ads.example.com^");
    let (engine, _) = c.build();
    // Three identical block rules + two identical host rules -> 2 active rules.
    assert_eq!(engine.len(), 2);
    assert!(engine.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(engine.check("dup.test", "A", &ci()).is_blocked());
}

#[test]
fn regexset_fallback_matches_multiple_regex_rules() {
    // Several regex rules land in the fallback RegexSet; all must still match.
    let e = compile_one("/^ads?\\./\n/tracker/\n/^[0-9]+cdn/");
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("x.tracker.net", "A", &ci()).is_blocked());
    assert!(e.check("123cdn.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}

#[test]
fn wildcard_reverse_index_correctness() {
    // Mix of wildcard rules; the token index must not change results vs a scan.
    let e = compile_one(
        "||*.doubleclick.net^\n*.ads.example.com\n||cdn-*.tracker.io^\n/^evil[0-9]+\\./",
    );
    assert!(e.check("x.doubleclick.net", "A", &ci()).is_blocked());
    assert!(e.check("a.b.ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("cdn-1.tracker.io", "A", &ci()).is_blocked());
    assert!(e.check("evil42.example.org", "A", &ci()).is_blocked()); // regex (fallback)
                                                                     // Non-matches.
    assert!(!e.check("doubleclick.net.evil.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.org", "A", &ci()).is_blocked());
}

#[test]
fn many_wildcards_match_fast() {
    // 20k wildcard rules; the reverse index should keep lookups quick while
    // remaining correct (a naive scan would check all 20k every query).
    let mut text = String::new();
    for i in 0..20_000 {
        text.push_str(&format!("||*.evilcdn{i}.example^\n"));
    }
    let e = compile_one(&text);
    let start = std::time::Instant::now();
    for i in 0..5_000 {
        let host = format!("node.evilcdn{}.example", i % 20_000);
        assert!(e.check(&host, "A", &ci()).is_blocked());
    }
    let elapsed = start.elapsed();
    // With the token index each lookup checks ~1 regex. A linear scan over 20k
    // rules would be ~20k regex evals per query (minutes); the index keeps this
    // well under the budget even in a debug build.
    assert!(
        elapsed.as_secs() < 10,
        "wildcard lookups too slow: {elapsed:?}"
    );
    assert!(!e.check("node.safe.example", "A", &ci()).is_blocked());
}

#[test]
fn large_list_matches_fast() {
    // Sanity: build 50k rules and ensure lookups are correct & quick.
    let mut text = String::new();
    for i in 0..50_000 {
        text.push_str(&format!("||evil{i}.example.com^\n"));
    }
    let e = compile_one(&text);
    assert_eq!(e.len(), 50_000);
    let start = std::time::Instant::now();
    for i in 0..10_000 {
        let _ = e.check(&format!("evil{}.example.com", i % 50_000), "A", &ci());
    }
    let elapsed = start.elapsed();
    // Should be well under a second for 10k lookups.
    assert!(elapsed.as_secs() < 2, "lookups too slow: {elapsed:?}");
    assert!(e.check("evil42.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}
