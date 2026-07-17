use std::collections::HashSet;

use onionroute_desktop_shell_model::{Screen, StringKey, SCREEN_SPECS};

#[test]
fn every_screen_is_reachable_and_named() {
    let screens: HashSet<_> = SCREEN_SPECS.iter().map(|spec| spec.screen).collect();
    assert_eq!(screens.len(), Screen::ALL.len());
    assert!(Screen::ALL.iter().all(|screen| screens.contains(screen)));
    assert!(SCREEN_SPECS
        .iter()
        .all(|spec| !spec.title.as_str().is_empty()));
}

#[test]
fn interactive_controls_have_labels_and_stable_focus_order() {
    for screen in SCREEN_SPECS {
        let mut focus = HashSet::new();
        for control in screen.controls {
            assert!(!control.id.is_empty());
            assert!(!control.accessibility_label.as_str().is_empty());
            assert!(control.focus_order > 0);
            assert!(focus.insert(control.focus_order));
        }
    }
}

#[test]
fn critical_controls_are_marked_for_confirmation() {
    let critical: Vec<_> = SCREEN_SPECS
        .iter()
        .flat_map(|screen| screen.controls)
        .filter(|control| control.critical)
        .map(|control| control.id)
        .collect();
    assert!(critical.contains(&"disconnect"));
    assert!(critical.contains(&"new-identity"));
    assert!(StringKey::A11yCriticalDialog.as_str().starts_with("a11y."));
}
