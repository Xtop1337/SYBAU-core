//! Selector and balancer outbound groups.

mod common;

use common::*;
use serde_json::{json, Value};

fn dead_port() -> u16 {
    // Nothing listens here once the probe socket is closed.
    free_port()
}

async fn group_info(core: &Core, tag: &str) -> Value {
    let list = core
        .engine
        .call("outbounds.list", &Value::Null)
        .await
        .unwrap();
    list.as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == tag)
        .unwrap()["group"]
        .clone()
}

#[tokio::test]
async fn selector_switches_and_remembers_across_reload() {
    let echo = spawn_echo().await;
    let config = json!({
        "outbounds": [
            {"type": "selector", "tag": "sel", "outbounds": ["a", "b"]},
            {"type": "direct", "tag": "a"},
            {"type": "direct", "tag": "b"},
        ],
    });
    let core = start_config(config.clone()).await;
    let p = echo.port();
    assert_eq!(core.which("127.0.0.1", p, b"one").await, Some("a"));
    assert_eq!(group_info(&core, "sel").await["now"], "a");

    core.engine
        .call(
            "outbounds.select",
            &json!({"group": "sel", "outbound": "b"}),
        )
        .await
        .unwrap();
    assert_eq!(core.which("127.0.0.1", p, b"two").await, Some("b"));
    assert!(core
        .engine
        .call(
            "outbounds.select",
            &json!({"group": "sel", "outbound": "zzz"})
        )
        .await
        .is_err());
    assert!(core
        .engine
        .call("outbounds.select", &json!({"group": "a", "outbound": "b"}))
        .await
        .is_err());

    // The choice survives a reload of the same configuration.
    let mut reload = config.clone();
    reload["inbounds"] = json!([{"type": "mixed", "tag": "in", "port": core.port}]);
    core.engine
        .call("core.reload", &json!({"config": reload}))
        .await
        .unwrap();
    assert_eq!(group_info(&core, "sel").await["now"], "b");
    assert_eq!(core.which("127.0.0.1", p, b"three").await, Some("b"));
    core.engine.stop().await;
}

#[tokio::test]
async fn round_robin_alternates() {
    let echo = spawn_echo().await;
    let core = start_config(json!({
        "outbounds": [
            {"type": "balancer", "tag": "lb", "outbounds": ["a", "b"]},
            {"type": "direct", "tag": "a"},
            {"type": "direct", "tag": "b"},
        ],
    }))
    .await;
    let mut seen = Vec::new();
    for i in 0..4 {
        seen.push(
            core.which("127.0.0.1", echo.port(), format!("req{i}").as_bytes())
                .await
                .unwrap(),
        );
    }
    assert_eq!(seen, ["a", "b", "a", "b"]);
    core.engine.stop().await;
}

#[tokio::test]
async fn fallback_skips_a_dead_member_and_remembers_it() {
    let echo = spawn_echo().await;
    let core = start_config(json!({
        "outbounds": [
            {"type": "balancer", "tag": "lb", "strategy": "fallback", "outbounds": ["dead", "a", "b"], "failure_cooldown": "1m"},
            {"type": "socks", "tag": "dead", "server": "127.0.0.1", "port": dead_port()},
            {"type": "direct", "tag": "a"},
            {"type": "direct", "tag": "b"},
        ],
    }))
    .await;
    assert_eq!(
        core.which("127.0.0.1", echo.port(), b"first").await,
        Some("a")
    );
    let info = group_info(&core, "lb").await;
    assert_eq!(info["strategy"], "fallback");
    assert_eq!(info["members"][0]["up"], false);
    assert_eq!(info["members"][0]["failures"], 1);
    // In cooldown the dead member is not tried again.
    assert_eq!(
        core.which("127.0.0.1", echo.port(), b"second").await,
        Some("a")
    );
    assert_eq!(group_info(&core, "lb").await["members"][0]["failures"], 1);
    core.engine.stop().await;
}

#[tokio::test]
async fn least_ping_measures_members() {
    let echo = spawn_echo().await;
    let core = start_config(json!({
        "outbounds": [
            {"type": "balancer", "tag": "lb", "strategy": "least_ping", "outbounds": ["a", "b"]},
            {"type": "direct", "tag": "a"},
            {"type": "direct", "tag": "b"},
        ],
    }))
    .await;
    for i in 0..3 {
        assert!(core
            .which("127.0.0.1", echo.port(), format!("x{i}").as_bytes())
            .await
            .is_some());
    }
    let info = group_info(&core, "lb").await;
    for m in info["members"].as_array().unwrap() {
        assert!(m["latency_ms"].as_f64().unwrap() > 0.0, "{info}");
    }
    core.engine.stop().await;
}

#[tokio::test]
async fn invalid_groups_are_rejected() {
    let engine = sybau_core::Engine::new(Default::default());
    for bad in [
        json!({"outbounds": [{"type": "selector", "tag": "s", "outbounds": ["s"]}]}),
        json!({"outbounds": [{"type": "selector", "tag": "s", "outbounds": ["x"]}]}),
        json!({"outbounds": [{"type": "selector", "tag": "s", "outbounds": []}]}),
        json!({"outbounds": [{"type": "selector", "tag": "s", "outbounds": ["d"], "default": "e"}, {"type": "direct", "tag": "d"}]}),
        json!({"outbounds": [{"type": "balancer", "tag": "b", "outbounds": ["d"], "strategy": "magic"}, {"type": "direct", "tag": "d"}]}),
        json!({"outbounds": [
            {"type": "selector", "tag": "s1", "outbounds": ["s2"]},
            {"type": "selector", "tag": "s2", "outbounds": ["s1"]},
        ]}),
    ] {
        assert!(
            engine
                .start(serde_json::from_value(bad.clone()).unwrap())
                .await
                .is_err(),
            "{bad}"
        );
    }
}
