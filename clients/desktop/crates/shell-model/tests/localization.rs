use std::collections::BTreeMap;

use onionroute_desktop_shell_model::StringKey;

fn catalog(source: &str) -> BTreeMap<String, String> {
    serde_json::from_str(source).unwrap()
}

#[test]
fn localization_catalogs_are_complete_and_nonempty() {
    let english = catalog(include_str!("../../../locales/en-US.json"));
    let russian = catalog(include_str!("../../../locales/ru-RU.json"));
    let required: Vec<_> = StringKey::ALL.iter().map(|key| key.as_str()).collect();
    for key in required {
        assert!(
            english
                .get(key)
                .is_some_and(|value| !value.trim().is_empty()),
            "missing en-US key {key}"
        );
        assert!(
            russian
                .get(key)
                .is_some_and(|value| !value.trim().is_empty()),
            "missing ru-RU key {key}"
        );
    }
    assert_eq!(
        english.keys().collect::<Vec<_>>(),
        russian.keys().collect::<Vec<_>>()
    );
}
