use super::*;
use serde_json::json;

fn cwd_mutate_floor(component: &str) -> serde_json::Value {
    json!({
        "cap": "path:cwd-mutate",
        "resource": {
            "kind": "path-exact",
            "path": {
                "root": "project",
                "components": [{"encoding": "utf8", "value": component}],
            }
        }
    })
}

fn cwd_observe_authority() -> serde_json::Value {
    json!({
        "cap": "path:cwd-observe",
        "resource": {"kind": "session-state", "name": "cwd"},
    })
}

fn expose_process_builtin(snapshot: &mut serde_json::Value) {
    snapshot["principals"][0]["imports"]["builtins"] = json!(["node:process"]);
}

#[cfg(unix)]
fn package_fixture_principal(
    name: &str,
    locator: &str,
    root: &std::path::Path,
) -> serde_json::Value {
    json!({
        "kind": "package",
        "name": name,
        "integrity": crate::module_loader::package_tree_integrity(root)
            .expect("digest package fixture"),
        "locator": locator,
    })
}

#[cfg(unix)]
fn package_fixture_binding(
    principal: &serde_json::Value,
    root: &std::path::Path,
) -> serde_json::Value {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(root).expect("stat package fixture");
    let components = root
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(value) => Some(json!({
                "encoding": "utf8",
                "value": value.to_str().expect("test path must be UTF-8"),
            })),
            _ => None,
        })
        .collect::<Vec<_>>();
    json!({
        "logicalRoot": "package",
        "owner": principal,
        "hostPath": {
            "root": "absolute",
            "components": components,
            "hostBound": true,
        },
        "object": {
            "platform": if cfg!(any(target_os = "macos", target_os = "ios", target_os = "tvos")) {
                "apple"
            } else {
                "unix"
            },
            "volume": format!("dev:{}", metadata.dev()),
            "file": format!("ino:{}", metadata.ino()),
        },
    })
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn builtin_process_chdir_does_not_observe_after_a_successful_mutation() {
    let _lock = hermes_engine_test_lock().lock().await;
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::create_dir(root.join("allowed")).unwrap();
    let (host, digest) = build_armed_test_host_custom(
        Some(&root),
        false,
        false,
        true,
        vec![cwd_mutate_floor("allowed")],
        None,
        |snapshot| {
            expose_process_builtin(snapshot);
            snapshot["principals"][0]["denials"] = json!([cwd_observe_authority()]);
        },
    );
    let native_error = host
        .resolve_module_meta_for_principal("./marker.js", None, Some("0"))
        .expect_err("armed native resolution must reject a missing virtual referrer");
    assert!(
        native_error
            .to_string()
            .contains("requires an authenticated virtual referrer"),
        "unexpected direct native resolution error: {native_error:#}"
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
    engine.load_runtime().await.unwrap();
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

    assert!(crate::host::abi::begin_installed_conformance_observation(
        "public.node-process.chdir.mutate-without-observe"
    ));
    let value = evaluator
        .eval_string(
            &engine,
            "var p = require('node:process'); p.chdir('/project/allowed'); 'ok'",
        )
        .await;

    let (legacy, observed) = crate::host::abi::take_installed_conformance_observations();
    assert_eq!(value, "ok");
    assert!(legacy.is_empty());
    assert_eq!(
        observed.len(),
        2,
        "cwd mutation must have Requested and Commit decisions"
    );
    assert_eq!(
        observed
            .iter()
            .map(|decision| decision.decision_set.context.stage)
            .collect::<Vec<_>>(),
        vec![
            capsec_semantics::model::Stage::Requested,
            capsec_semantics::model::Stage::Commit,
        ]
    );
    assert!(observed.iter().all(|decision| {
        decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Allow
            && decision
                .decision_set
                .effects
                .iter()
                .any(|effect| effect.action.as_str() == "path:cwd-mutate")
            && decision
                .decision_set
                .effects
                .iter()
                .all(|effect| effect.action.as_str() != "path:cwd-observe")
    }));
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn builtin_process_chdir_denial_does_not_trigger_cwd_observation() {
    let _lock = hermes_engine_test_lock().lock().await;
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::create_dir(root.join("denied")).unwrap();
    let (host, digest) =
        build_armed_test_host_custom(Some(&root), false, false, true, vec![], None, |snapshot| {
            expose_process_builtin(snapshot);
            snapshot["principals"][0]["denials"] = json!([cwd_mutate_floor("denied")]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
    engine.load_runtime().await.unwrap();
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

    assert!(crate::host::abi::begin_installed_conformance_observation(
        "public.node-process.chdir.denied-without-observe"
    ));
    let error = evaluator
        .eval_string(
            &engine,
            "var p = require('node:process'); try { p.chdir('/project/denied'); 'unexpected'; } catch (e) { String(e && e.message || e); }",
        )
        .await;
    assert!(error.contains("EACCES"), "unexpected chdir denial: {error}");

    let (legacy, observed) = crate::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert_eq!(observed.len(), 1, "denial must stop before Commit");
    assert_eq!(
        observed[0].decision_set.context.stage,
        capsec_semantics::model::Stage::Requested
    );
    assert_eq!(
        observed[0].evidence.outcome,
        capsec_semantics::decision::DecisionOutcome::Deny
    );
    assert!(observed[0]
        .decision_set
        .effects
        .iter()
        .any(|effect| effect.action.as_str() == "path:cwd-mutate"));
    assert!(observed[0]
        .decision_set
        .effects
        .iter()
        .all(|effect| effect.action.as_str() != "path:cwd-observe"));
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn empty_referrer_relative_require_uses_the_authenticated_virtual_cwd() {
    let _lock = hermes_engine_test_lock().lock().await;
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let base = root.join("virtual-base");
    std::fs::create_dir(&base).unwrap();
    std::fs::write(
        base.join("marker.js"),
        "module.exports = 'virtual-cwd-target';",
    )
    .unwrap();
    let (host, digest) = build_armed_test_host_custom(
        Some(&root),
        false,
        true,
        true,
        vec![cwd_mutate_floor("virtual-base"), cwd_observe_authority()],
        None,
        expose_process_builtin,
    );
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
    engine.load_runtime().await.unwrap();
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

    let value = evaluator
        .eval_string(
            &engine,
            "var p = require('node:process'); p.chdir('/project/virtual-base'); String(require('./marker.js'))",
        )
        .await;
    assert_eq!(value, "virtual-cwd-target");
}

#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn cwd_denial_stops_empty_referrer_module_entry_points_before_resolution() {
    let _lock = hermes_engine_test_lock().lock().await;
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    std::fs::write(root.join("marker.js"), "module.exports = 'must-not-load';").unwrap();
    let (host, digest) =
        build_armed_test_host_custom(Some(&root), false, true, true, vec![], None, |snapshot| {
            snapshot["principals"][0]["denials"] = json!([cwd_observe_authority()]);
        });
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
    engine.load_runtime().await.unwrap();
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

    assert!(crate::host::abi::begin_installed_conformance_observation(
        "public.module-loader.relative-cwd.denied"
    ));
    let value = evaluator
        .eval_string(
            &engine,
            r#"var errors = [];
                try { require('./marker.js'); errors.push('unexpected-load'); }
                catch (e) { errors.push(String(e && e.message || e)); }
                try { require.resolve('./marker.js'); errors.push('unexpected-resolve'); }
                catch (e) { errors.push(String(e && e.message || e)); }
                try { await globalThis.import('./marker.js'); errors.push('unexpected-import'); }
                catch (e) { errors.push(String(e && e.message || e)); }
                JSON.stringify(errors)"#,
        )
        .await;
    let errors: Vec<String> = serde_json::from_str(&value).unwrap();
    assert_eq!(errors.len(), 3);
    assert!(errors.iter().all(|error| error.contains("EACCES: cwd")));

    let (legacy, observed) = crate::host::abi::take_installed_conformance_observations();
    assert!(legacy.is_empty());
    assert_eq!(observed.len(), 3);
    assert!(observed.iter().all(|decision| {
        decision.decision_set.context.stage == capsec_semantics::model::Stage::Requested
            && decision.evidence.outcome == capsec_semantics::decision::DecisionOutcome::Deny
            && decision.decision_set.effects.len() == 1
            && decision.decision_set.effects[0].action.as_str() == "path:cwd-observe"
    }));
}

// @ref LLP 0013#implementation-status — an import gate is keyed to the live
// requesting principal and must precede every module-cache shortcut.
// @ref LLP 0023#22-authorization-identity-is-caller-relative — a cached
// SourceId retains identity, not the authority of the principal that warmed it.
#[cfg(unix)]
#[tokio::test(flavor = "current_thread")]
#[cfg(not(feature = "insecure"))]
async fn authenticated_resolution_memo_reauthorizes_root_and_exact_locator_targets() {
    let _lock = hermes_engine_test_lock().lock().await;
    let temp = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(temp.path()).unwrap();
    let attacker_root = root.join("node_modules/image-lib");
    let allowed_locator_root = root.join("vendor-v1/node_modules/shared");
    let denied_locator_root = root.join("node_modules/shared");
    for package_root in [&attacker_root, &allowed_locator_root, &denied_locator_root] {
        std::fs::create_dir_all(package_root).unwrap();
    }
    std::fs::write(
        root.join("root-only.js"),
        r#"globalThis.__memoRootExecutions = (globalThis.__memoRootExecutions || 0) + 1;
module.exports = { marker: 'root', executions: globalThis.__memoRootExecutions };"#,
    )
    .unwrap();
    std::fs::write(
        attacker_root.join("package.json"),
        r#"{"name":"image-lib","version":"2.4.1","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        attacker_root.join("index.js"),
        "module.exports = function (loader, specifier) { return loader(specifier); };",
    )
    .unwrap();
    std::fs::write(
        allowed_locator_root.join("package.json"),
        r#"{"name":"shared","version":"1.0.0","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        allowed_locator_root.join("index.js"),
        "module.exports = { marker: 'allowed-decoy', executions: 1 };",
    )
    .unwrap();
    std::fs::write(
        denied_locator_root.join("package.json"),
        r#"{"name":"shared","version":"2.0.0","main":"index.js"}"#,
    )
    .unwrap();
    std::fs::write(
        denied_locator_root.join("index.js"),
        r#"globalThis.__memoV2Executions = (globalThis.__memoV2Executions || 0) + 1;
module.exports = { marker: 'v2', executions: globalThis.__memoV2Executions };"#,
    )
    .unwrap();

    let attacker = package_fixture_principal("image-lib", "image-lib@2.4.1", &attacker_root);
    let allowed_locator =
        package_fixture_principal("shared", "shared@1.0.0", &allowed_locator_root);
    let denied_locator = package_fixture_principal("shared", "shared@2.0.0", &denied_locator_root);
    let attacker_binding = package_fixture_binding(&attacker, &attacker_root);
    let allowed_locator_binding = package_fixture_binding(&allowed_locator, &allowed_locator_root);
    let denied_locator_binding = package_fixture_binding(&denied_locator, &denied_locator_root);
    let attacker_for_snapshot = attacker.clone();
    let allowed_locator_for_snapshot = allowed_locator.clone();
    let denied_locator_for_snapshot = denied_locator.clone();
    let (fixture_host, digest) = build_armed_test_host_custom(
        Some(&root),
        false,
        true,
        true,
        vec![cwd_observe_authority()],
        None,
        move |snapshot| {
            let root_principal = snapshot["principals"][0]["principal"].clone();
            snapshot["principals"][0]["imports"]["packages"] =
                json!(["image-lib@2.4.1", "shared@1.0.0", "shared@2.0.0"]);
            snapshot["principals"][1] = json!({
                "principal": attacker_for_snapshot,
                "floor": [cwd_observe_authority()],
                "denials": [],
                "escalationCeiling": [],
                "imports": {"builtins": [], "packages": ["shared@1.0.0"]},
                "endowments": [],
            });
            snapshot["principals"].as_array_mut().unwrap().extend([
                json!({
                    "principal": allowed_locator_for_snapshot,
                    "floor": [],
                    "denials": [],
                    "escalationCeiling": [],
                    "imports": {"builtins": [], "packages": []},
                    "endowments": [],
                }),
                json!({
                    "principal": denied_locator_for_snapshot,
                    "floor": [],
                    "denials": [],
                    "escalationCeiling": [],
                    "imports": {"builtins": [], "packages": []},
                    "endowments": [],
                }),
            ]);
            snapshot["packageGraph"]["nodes"] = json!([
                {"principal": attacker},
                {"principal": allowed_locator},
                {"principal": denied_locator},
            ]);
            snapshot["packageGraph"]["importEdges"] = json!([
                {"importer": root_principal, "imported": attacker},
                {"importer": root_principal, "imported": allowed_locator},
                {"importer": root_principal, "imported": denied_locator},
                {
                    "importer": root_principal,
                    "imported": denied_locator,
                    "requestSpecifier": "./node_modules/shared/index.js",
                    "resolutionKind": "common-js-require",
                    "conditions": ["node", "require"],
                    "attributes": {}
                },
                {
                    "importer": root_principal,
                    "imported": allowed_locator,
                    "requestSpecifier": "./vendor-v1/node_modules/shared/index.js",
                    "resolutionKind": "common-js-require",
                    "conditions": ["node", "require"],
                    "attributes": {}
                },
                {"importer": attacker, "imported": allowed_locator},
            ]);
            snapshot["rootBindings"][0] = attacker_binding;
            snapshot["rootBindings"]
                .as_array_mut()
                .unwrap()
                .extend([allowed_locator_binding, denied_locator_binding]);
            snapshot["rootBindings"]
                .as_array_mut()
                .unwrap()
                .retain(|binding| binding["logicalRoot"] != "absolute");
        },
    );
    let host = unsafe {
        crate::host::Host::new_armed_for_test_with_package_sources(
            crate::host::HostConfig {
                mode: crate::host::SecurityMode::Enforce,
                ..Default::default()
            },
            fixture_host.armed_snapshot().unwrap().clone(),
        )
    }
    .expect("package memo fixture must authenticate every package source object");
    host.resolve_module_meta_for_principal(
        "./node_modules/shared/index.js",
        Some(&root.join(".ibex-cwd-resolution-base.js")),
        Some("0"),
    )
    .expect("root principal must be able to warm the denied-locator target");
    assert_ne!(crate::host::abi::install_host(host.clone()), 0);
    let _reset = HostResetGuard;
    let engine = HermesEngine::new_with_armed_snapshot(Some(&digest)).unwrap();
    engine.load_runtime().await.unwrap();
    let mut evaluator = AuthenticatedReplTestEvaluator::new(&host);

    let value = evaluator
        .eval_string(
            &engine,
            r#"var rootWarm;
                var locatorWarm;
                var allowedLocatorWarm;
                var attacker;
                var warmErrors = [];
                try { rootWarm = globalThis.require('./root-only.js'); }
                catch (error) { warmErrors.push('root:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                var dynamicRoot;
                try { dynamicRoot = await globalThis.import('./root-only.js'); }
                catch (error) { warmErrors.push('dynamic-root:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                try { locatorWarm = globalThis.require('./node_modules/shared/index.js'); }
                catch (error) { warmErrors.push('locator:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                try { allowedLocatorWarm = globalThis.require('./vendor-v1/node_modules/shared/index.js'); }
                catch (error) { warmErrors.push('allowed-locator:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                try { attacker = require('image-lib'); }
                catch (error) { warmErrors.push('attacker:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                var dynamicAttacker;
                try { dynamicAttacker = await globalThis.import('image-lib'); }
                catch (error) { warmErrors.push('dynamic-attacker:' + String(error && error.code || '') + ':' + String(error && error.message || error)); }
                function attempt(specifier) {
                  if (typeof attacker !== 'function') {
                    return { code: 'WARM_FAILED', message: warmErrors.join('|') };
                  }
                  try {
                    attacker(globalThis.require, specifier);
                    return { code: 'ALLOWED', message: '' };
                  } catch (error) {
                    return {
                      code: String(error && error.code || ''),
                      message: String(error && error.message || error)
                    };
                  }
                }
                JSON.stringify({
                  root: attempt('./root-only.js'),
                  locator: attempt('./node_modules/shared/index.js'),
                  allowedLocator: attempt('./vendor-v1/node_modules/shared/index.js'),
                  warmErrors: warmErrors,
                  rootExecutions: rootWarm && rootWarm.executions,
                  dynamicRootExecutions: dynamicRoot && dynamicRoot.default && dynamicRoot.default.executions,
                  dynamicAttackerType: typeof (dynamicAttacker && dynamicAttacker.default),
                  locatorExecutions: locatorWarm && locatorWarm.executions,
                  allowedLocatorMarker: allowedLocatorWarm && allowedLocatorWarm.marker
                })"#,
        )
        .await;
    let result: serde_json::Value = serde_json::from_str(&value).unwrap();
    assert_eq!(result["warmErrors"], json!([]), "{result}");
    assert_eq!(result["root"]["code"], "ERR_IBEX_IMPORT_DENIED", "{result}");
    assert_eq!(
        result["locator"]["code"], "ERR_IBEX_IMPORT_DENIED",
        "{result}"
    );
    assert_eq!(
        result["allowedLocator"]["code"], "ERR_IBEX_IMPORT_DENIED",
        "{result}"
    );
    assert_eq!(result["rootExecutions"], 1, "{result}");
    assert_eq!(result["dynamicRootExecutions"], 1, "{result}");
    assert_eq!(result["dynamicAttackerType"], "function", "{result}");
    assert_eq!(result["locatorExecutions"], 1, "{result}");
    assert_eq!(result["allowedLocatorMarker"], "allowed-decoy", "{result}");
}
