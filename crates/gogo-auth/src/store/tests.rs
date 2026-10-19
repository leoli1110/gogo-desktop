use super::*;

const PW: &str = "correct horse battery";

fn store_with_admin() -> (Store, User) {
    let s = Store::open_in_memory().unwrap();
    let a = s.create_local_user("admin", PW, Role::Admin).unwrap();
    (s, a)
}

#[test]
fn create_and_sign_in() {
    let (s, a) = store_with_admin();
    assert_eq!(a.role, Role::Admin);
    assert!(matches!(s.create_local_user("admin", PW, Role::User), Err(StoreError::Duplicate)));
    assert!(matches!(s.create_local_user("ADMIN", PW, Role::User), Err(StoreError::Duplicate)));
    assert!(matches!(s.create_local_user("bob", "short", Role::User), Err(StoreError::Password(_))));
    assert!(matches!(s.create_local_user("-bad", PW, Role::User), Err(StoreError::Invalid(_))));
    assert_eq!(s.authenticate_local("admin", PW, None, false).unwrap().id, a.id);
    assert_eq!(
        s.authenticate_local("admin", "wrong password!!", None, false).unwrap_err(),
        AuthError::InvalidCredentials
    );
    assert_eq!(s.authenticate_local("nobody", PW, None, false).unwrap_err(), AuthError::InvalidCredentials);
}

#[test]
fn lockout_after_five_failures() {
    let (s, _) = store_with_admin();
    for _ in 0..5 {
        assert_eq!(
            s.authenticate_local("admin", "wrong password!!", None, false).unwrap_err(),
            AuthError::InvalidCredentials
        );
    }
    assert!(matches!(s.authenticate_local("admin", PW, None, false), Err(AuthError::Locked { .. })));
    let id = s.user_by_name("admin").unwrap().unwrap().id;
    s.unlock(id).unwrap();
    assert!(s.authenticate_local("admin", PW, None, false).is_ok());
}

#[test]
fn admins_only_mode() {
    let (s, _) = store_with_admin();
    s.create_local_user("bob", PW, Role::User).unwrap();
    assert_eq!(s.authenticate_local("bob", PW, None, true).unwrap_err(), AuthError::NotAllowed);
    assert!(s.authenticate_local("admin", PW, None, true).is_ok());
}

#[test]
fn last_admin_is_protected() {
    let (s, a) = store_with_admin();
    assert!(matches!(s.set_role(a.id, Role::User), Err(StoreError::LastAdmin)));
    assert!(matches!(s.set_disabled(a.id, true), Err(StoreError::LastAdmin)));
    assert!(matches!(s.delete_user(a.id), Err(StoreError::LastAdmin)));
    let b = s.create_local_user("second", PW, Role::Admin).unwrap();
    s.set_role(a.id, Role::User).unwrap();
    assert!(matches!(s.delete_user(b.id), Err(StoreError::LastAdmin)));
    // A Windows administrator doesn't count as the emergency administrator.
    let w = s.windows_user("S-1-5-21-1", "PC\\leo").unwrap();
    s.set_role(w.id, Role::Admin).unwrap();
    assert!(matches!(s.set_disabled(b.id, true), Err(StoreError::LastAdmin)));
}

#[test]
fn second_factor() {
    let (s, a) = store_with_admin();
    let secret = s.totp_begin(a.id).unwrap();
    assert!(s.totp_confirm(a.id, "000000").is_err());
    let code = totp::code_at(&secret, now() / totp::PERIOD).unwrap();
    s.totp_confirm(a.id, &code).unwrap();
    assert!(s.user(a.id).unwrap().totp_enabled);
    assert_eq!(s.authenticate_local("admin", PW, None, false).unwrap_err(), AuthError::CodeRequired);
    // The confirming code can't be replayed for sign-in.
    assert_eq!(s.authenticate_local("admin", PW, Some(&code), false).unwrap_err(), AuthError::BadCode);
    let next = totp::code_at(&secret, now() / totp::PERIOD + 1).unwrap();
    assert!(s.authenticate_local("admin", PW, Some(&next), false).is_ok());
}

#[test]
fn sessions_expire_and_end_on_disable() {
    let (s, _) = store_with_admin();
    let bob = s.create_local_user("bob", PW, Role::User).unwrap();
    let p = SessionPolicy::default();
    let (tok, sess) = s.create_session(bob.id, "password", "127.0.0.1", p).unwrap();
    assert_eq!(sess.csrf.len(), 43);
    assert_eq!(s.session(&tok, p).unwrap().unwrap().1.id, bob.id);
    assert!(s.session("nope", p).unwrap().is_none());
    // Idle limit
    let short = SessionPolicy { idle_secs: 0, absolute_secs: 100 };
    assert!(s.session(&tok, short).unwrap().is_none());
    let (tok, _) = s.create_session(bob.id, "password", "127.0.0.1", p).unwrap();
    s.set_disabled(bob.id, true).unwrap();
    assert!(s.session(&tok, p).unwrap().is_none());
}

#[test]
fn password_change_ends_other_sessions() {
    let (s, a) = store_with_admin();
    let p = SessionPolicy::default();
    let (t1, _) = s.create_session(a.id, "password", "", p).unwrap();
    let (t2, _) = s.create_session(a.id, "password", "", p).unwrap();
    s.set_password(a.id, "another long passphrase", Some(&t1)).unwrap();
    assert!(s.session(&t1, p).unwrap().is_some());
    assert!(s.session(&t2, p).unwrap().is_none());
    assert!(s.authenticate_local("admin", "another long passphrase", None, false).is_ok());
}

#[test]
fn library_permissions() {
    let (s, a) = store_with_admin();
    let bob = s.create_local_user("bob", PW, Role::User).unwrap();
    let carol = s.create_local_user("carol", PW, Role::User).unwrap();
    let l1 = s.add_library("Projects", "/libraries/Projects", Some("\\\\NAS\\Projects"), "config").unwrap();
    let l2 = s.add_library("Photos", "/libraries/Photos", None, "config").unwrap();
    assert!(matches!(s.add_library("projects", "/x", None, "admin"), Err(StoreError::Duplicate)));
    // New libraries: administrators only.
    assert_eq!(s.libraries_for(&a).unwrap().len(), 2);
    assert!(s.libraries_for(&bob).unwrap().is_empty());
    s.set_library_access(l1.id, &[format!("user:{}", bob.id)]).unwrap();
    s.set_library_access(l2.id, &["role:user".into()]).unwrap();
    let mut b = s.libraries_for(&bob).unwrap();
    b.sort();
    assert_eq!(b, vec![l1.id, l2.id]);
    assert_eq!(s.libraries_for(&carol).unwrap(), vec![l2.id]);
    assert!(s.set_library_access(l1.id, &["user:999".into()]).is_err());
    assert!(s.set_library_access(l1.id, &["role:admin; DROP".into()]).is_err());
    s.delete_user(bob.id).unwrap();
    assert!(s.library(l1.id).unwrap().access.is_empty());
}

#[test]
fn reset_code_recovers_admin() {
    let (s, a) = store_with_admin();
    s.totp_begin(a.id).unwrap();
    for _ in 0..5 {
        let _ = s.authenticate_local("admin", "wrong password!!", None, false);
    }
    let code = s.create_reset_code().unwrap();
    assert!(s.use_reset_code("WRONG-CODE-0000", "admin", "brand new passphrase").is_err());
    let u = s.use_reset_code(&code.to_lowercase(), "admin", "brand new passphrase").unwrap();
    assert!(!u.totp_enabled);
    assert!(s.authenticate_local("admin", "brand new passphrase", None, false).is_ok());
    assert!(s.use_reset_code(&code, "admin", "yet another passphrase").is_err(), "single use");
}

#[test]
fn windows_accounts() {
    let (s, _) = store_with_admin();
    let w = s.windows_user("S-1-5-21-42", "PC\\leo").unwrap();
    assert_eq!(w.kind, AccountKind::Windows);
    assert_eq!(w.role, Role::User);
    assert_eq!(s.windows_user("S-1-5-21-42", "PC\\leo").unwrap().id, w.id);
    // Windows accounts have no password sign-in.
    assert_eq!(s.authenticate_local("PC\\leo", PW, None, false).unwrap_err(), AuthError::InvalidCredentials);
}
