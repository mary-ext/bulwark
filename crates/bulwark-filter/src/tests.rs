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
fn redundant_child_pruned_verdict_preserved() {
    let e = compile_one("||doubleclick.net^\n||ads.doubleclick.net^");
    assert_eq!(e.len(), 1, "redundant child should be pruned");
    assert!(e.check("doubleclick.net", "A", &ci()).is_blocked());
    assert!(e.check("ads.doubleclick.net", "A", &ci()).is_blocked());
    assert!(e.check("x.ads.doubleclick.net", "A", &ci()).is_blocked());
}

#[test]
fn exact_host_under_subdomain_pruned() {
    let e = compile_one("||example.com^\n0.0.0.0 ads.example.com");
    assert_eq!(e.len(), 1);
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
}

#[test]
fn unrelated_and_exact_only_rules_not_pruned() {
    assert_eq!(compile_one("||a.com^\n||b.com^").len(), 2);
    assert_eq!(
        compile_one("0.0.0.0 example.com\n0.0.0.0 ads.example.com").len(),
        2
    );
}

#[test]
fn allow_wildcard_overrides_domain_block() {
    let e = compile_one("||example.com^\n@@/^sub\\.example\\.com$/");
    assert!(e.check("other.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("sub.example.com", "A", &ci()).is_blocked());
}

#[test]
fn important_wildcard_overrides_domain_allow() {
    let e = compile_one("@@||example.com^\n/tracker\\.example\\.com/$important");
    assert!(e.check("tracker.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}

#[test]
fn block_only_wildcard_matches_without_domain_rule() {
    let e = compile_one("/^ads[0-9]+\\.example\\.net$/");
    assert!(e.check("ads123.example.net", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.net", "A", &ci()).is_blocked());
}

#[test]
fn special_children_kept_despite_blocked_parent() {
    let e = compile_one(
        "||example.com^\n\
         @@||ok.example.com^\n\
         ||imp.example.com^$important\n\
         ||typed.example.com^$dnstype=AAAA",
    );
    assert_eq!(e.len(), 4, "exception/important/modified children are kept");
    assert!(!e.check("ok.example.com", "A", &ci()).is_blocked());
    assert!(e.check("imp.example.com", "A", &ci()).is_blocked());
}

#[test]
fn exception_unblocks() {
    let e = compile_one("||example.com^\n@@||good.example.com^");
    assert!(e.check("bad.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("good.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("x.good.example.com", "A", &ci()).is_blocked());
}

#[test]
fn important_beats_exception() {
    let e = compile_one("@@||example.com^\n||tracker.example.com^$important");
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
fn bare_ip_literals_block_exactly() {
    let e = compile_one("1.2.3.4\n1234::cdef\n");
    assert!(e.check("1.2.3.4", "A", &ci()).is_blocked());
    assert!(e.check("1234::cdef", "AAAA", &ci()).is_blocked());
    assert!(!e.check("1.2.3.5", "A", &ci()).is_blocked());
    assert!(!e.check("1234::cdee", "AAAA", &ci()).is_blocked());
}

#[test]
fn v6_literal_is_canonicalized() {
    let e = compile_one("2001:0DB8:0000:0000:0000:0000:0000:0001");
    assert!(e.check("2001:db8::1", "AAAA", &ci()).is_blocked());
}

#[test]
fn bracketed_and_anchored_v6_rule() {
    let e = compile_one("||[2606:4700::1111]^");
    assert!(e.check("2606:4700::1111", "AAAA", &ci()).is_blocked());
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
    let mut c = Compiler::new();
    c.add_list(1, "a", "||ads.example.com^\n0.0.0.0 dup.test");
    c.add_list(2, "b", "||ads.example.com^\n0.0.0.0 dup.test");
    c.add_list(3, "c", "||ads.example.com^");
    let (engine, _) = c.build();
    assert_eq!(engine.len(), 2);
    assert!(engine.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(engine.check("dup.test", "A", &ci()).is_blocked());
}

#[test]
fn regexset_fallback_matches_multiple_regex_rules() {
    let e = compile_one("/^ads?\\./\n/tracker/\n/^[0-9]+cdn/");
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("x.tracker.net", "A", &ci()).is_blocked());
    assert!(e.check("123cdn.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}

#[test]
fn wildcard_reverse_index_correctness() {
    let e = compile_one(
        "||*.doubleclick.net^\n*.ads.example.com\n||cdn-*.tracker.io^\n/^evil[0-9]+\\./",
    );
    assert!(e.check("x.doubleclick.net", "A", &ci()).is_blocked());
    assert!(e.check("a.b.ads.example.com", "A", &ci()).is_blocked());
    assert!(e.check("cdn-1.tracker.io", "A", &ci()).is_blocked());
    assert!(e.check("evil42.example.org", "A", &ci()).is_blocked()); // regex (fallback)
    assert!(!e.check("doubleclick.net.evil.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.org", "A", &ci()).is_blocked());
}

#[test]
fn many_wildcards_match_fast() {
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
    assert!(
        elapsed.as_secs() < 10,
        "wildcard lookups too slow: {elapsed:?}"
    );
    assert!(!e.check("node.safe.example", "A", &ci()).is_blocked());
}

#[test]
fn large_list_matches_fast() {
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
    assert!(elapsed.as_secs() < 2, "lookups too slow: {elapsed:?}");
    assert!(e.check("evil42.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}

#[test]
fn empty_scoped_modifier_drops_rule_not_match_all() {
    for rule in [
        "||corp.example^$client=",
        "||corp.example^$ctag=",
        "||corp.example^$dnstype=",
        "||corp.example^$denyallow=",
    ] {
        let e = compile_one(rule);
        assert_eq!(e.len(), 0, "rule should be dropped: {rule:?}");
        let some_client = ClientInfo {
            ip: Some("10.0.0.1".parse().unwrap()),
            ..Default::default()
        };
        assert!(
            !e.check("corp.example", "A", &some_client).is_blocked(),
            "empty modifier must not match-all: {rule:?}"
        );
    }
    let e = compile_one("||corp.example^$client=10.0.0.1");
    let target = ClientInfo {
        ip: Some("10.0.0.1".parse().unwrap()),
        ..Default::default()
    };
    let other = ClientInfo {
        ip: Some("10.0.0.2".parse().unwrap()),
        ..Default::default()
    };
    assert!(e.check("corp.example", "A", &target).is_blocked());
    assert!(!e.check("corp.example", "A", &other).is_blocked());
}

#[test]
fn cosmetic_rules_are_skipped() {
    for rule in [
        "example.com##.ad-banner",
        "example.com#@#.ad",
        "example.com#?#div:has(> .ad)",
        "example.com#$#body { color: red }",
        "example.com#%#//scriptlet('foo')",
        "example.com$$script[data-ad]",
    ] {
        let e = compile_one(rule);
        assert_eq!(e.len(), 0, "cosmetic rule should be skipped: {rule:?}");
        assert!(
            !e.check("example.com", "A", &ci()).is_blocked(),
            "cosmetic rule must not block the domain: {rule:?}"
        );
    }
    let e = compile_one("0.0.0.0 ads.example.com ## inline note");
    assert!(e.check("ads.example.com", "A", &ci()).is_blocked());
}

#[test]
fn non_dns_hostname_patterns_rejected() {
    for rule in [
        "||example.com/path^", // URL path
        "||has space^",        // whitespace
        "||foo|bar^",          // stray pipe (not a valid host)
    ] {
        let e = compile_one(rule);
        assert_eq!(e.len(), 0, "non-DNS pattern should be rejected: {rule:?}");
    }
    assert_eq!(compile_one("||xn--80ak6aa92e.com^").len(), 1);
    assert_eq!(compile_one("||_dmarc.example.com^").len(), 1);
}

#[test]
fn oversized_regex_rule_rejected() {
    let long = "a".repeat(2000);
    let e = compile_one(&format!("/{long}/"));
    assert_eq!(e.len(), 0, "over-long regex rule should be dropped");
    let e = compile_one(r"/^ads\d+\./");
    assert!(e.check("ads42.example.com", "A", &ci()).is_blocked());
}

#[test]
fn many_regex_fallback_rules_match_across_chunks() {
    let mut text = String::new();
    for i in 0..600 {
        text.push_str(&format!("/^ads{i}\\./\n"));
    }
    let e = compile_one(&text);
    assert_eq!(e.len(), 600);
    assert!(e.check("ads0.example.com", "A", &ci()).is_blocked());
    assert!(e.check("ads599.example.com", "A", &ci()).is_blocked());
    assert!(!e.check("safe.example.com", "A", &ci()).is_blocked());
}
