#![deny(unused_must_use)]

#[macro_use]
extern crate log;

use std::borrow::Cow;
use std::cell::RefCell;
use std::rc::Rc;

use chrono::{DateTime, Utc};
use cursive::Cursive;
use cursive::event::Key as KeyEvent;
use cursive::theme::{Palette, BaseColor, Color, Theme};
use cursive::traits::*;
use cursive::utils::markup::StyledString;
use cursive::view::SizeConstraint;
use cursive::views::{BoxView, Dialog, DummyView, LinearLayout, PaddedView, Panel, ScrollView, SelectView, TextView};
use uuid::Uuid;

use rusty_kms::misc::get_password_from_tty;
use rusty_kms::authorisation::{Authorisation, AuthorisationError, Access};
use rusty_kms::key_store::{Store, AliasArn, Lookup, Key};

type SelectKeyView = SelectView<Uuid>;

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("browser=info")).init();

    let app = clap::App::new("Rusty KMS store browser").version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name("data-path")
            .help("Key store directory")
            .required(true)
            .takes_value(true));
    let args = app.get_matches();
    let key_store = Store::with_persistence(args.value_of("data-path").unwrap(), get_password_from_tty)
        .unwrap_or_else(|e| {
            error!("Cannot open key store: {}", e);
            std::process::exit(1);
        });
    let browser = Browser { key_store };
    show_browser(browser);
}

fn show_browser(browser: Browser) {
    let mut siv = Cursive::default();
    siv.add_global_callback('q', Cursive::quit);

    let mut theme = Theme::default();
    let mut palette = Palette::default();
    palette.set_color("background", Color::Dark(BaseColor::Black));
    palette.set_color("shadow", Color::Light(BaseColor::Black));
    palette.set_color("title_primary", Color::Dark(BaseColor::Blue));
    palette.set_color("highlight", Color::Light(BaseColor::Blue));
    palette.set_color("highlight_inactive", Color::Dark(BaseColor::Blue));
    theme.palette = palette;
    siv.set_theme(theme);

    let browser = Rc::new(RefCell::new(browser));

    let browser_clone = Rc::clone(&browser);
    let delete_lock = Rc::new(RefCell::new(false));
    siv.add_global_callback(KeyEvent::Backspace, move |s: &mut Cursive| {
        if *delete_lock.borrow() {
            return;
        }
        if let Some(key_id) = s.find_id::<SelectKeyView>("list")
            .map(|view| view.selection())
            .unwrap_or(None) {
            if key_id.is_nil() {
                return;
            }
            *delete_lock.borrow_mut() = true;
            let delete_lock1 = Rc::clone(&delete_lock);
            let delete_lock2 = Rc::clone(&delete_lock);
            let browser = Rc::clone(&browser_clone);
            let prompt = Dialog::text("Do you want to delete this key?")
                .button("Cancel", move |s: &mut Cursive| {
                    s.pop_layer();
                    *delete_lock1.borrow_mut() = false;
                })
                .button("Delete", move |s: &mut Cursive| {
                    let mut browser = browser.borrow_mut();
                    browser.delete_key(&key_id);
                    s.call_on_id("list", |list_view: &mut SelectKeyView| {
                        list_view.clear();
                        refresh_list(list_view, browser.key_list());
                    }).unwrap();
                    s.call_on_id("detail", |text_view: &mut TextView| {
                        text_view.set_content("Select a key")
                    }).unwrap();
                    s.pop_layer();
                    *delete_lock2.borrow_mut() = false;
                });
            s.add_layer(prompt);
        }
    });

    let detail_view = TextView::new("Select a key");
    let mut list_view: SelectKeyView = SelectView::new();
    refresh_list(&mut list_view, browser.borrow().key_list());
    list_view.set_on_submit(move |s, key_id: &Uuid| {
        if key_id.is_nil() {
            return;
        }
        s.call_on_id("detail", |text_view: &mut TextView| {
            browser.borrow().display_details(text_view, key_id);
        }).unwrap();
    });

    let list_view = BoxView::new(
        SizeConstraint::AtLeast(38), SizeConstraint::Full,
        Panel::new(ScrollView::new(list_view.with_id("list"))).title("Keys")
    );
    let detail_view = BoxView::with_full_width(
        Panel::new(detail_view.with_id("detail")).title("Details")
    );
    let status_bar = PaddedView::new(
        ((1, 1), (1, 0)),
        TextView::new("Press Q to exit")
    );
    let root_view = LinearLayout::vertical()
        .child(
            LinearLayout::horizontal()
                .child(list_view)
                .child(DummyView)
                .child(detail_view)
        )
        .child(status_bar);

    siv.add_fullscreen_layer(root_view);
    siv.run();
}

fn refresh_list(list_view: &mut SelectKeyView, key_list: Vec<(String, Uuid)>) {
    list_view.add_all(key_list);
    if list_view.is_empty() {
        list_view.add_item("(None)", Uuid::nil());
    }
    // TODO: need to trigger layout?
}

struct Browser {
    key_store: Store,
}

impl Browser {
    fn key_list(&self) -> Vec<(String, Uuid)> {
        let mut key_list: Vec<(&DateTime<Utc>, &Uuid)> = self.key_store.authorised_keys(&BrowserAuthorisation)
            .map(|key| (key.created(), key.key_id()))
            .collect();
        key_list.sort_by_key(|&(created, _)| created);
        key_list.reverse();
        key_list.iter()
            .map(|&(_, key_id)| (key_id.to_hyphenated().to_string(), key_id.to_owned()))
            .collect()
    }

    fn display_details(&self, text_view: &mut TextView, key_id: &Uuid) {
        let lookup = Lookup::KeyId(Cow::Borrowed(key_id));
        let key = self.key_store.authorised_get(&BrowserAuthorisation, Access::Default, lookup)
            .expect("cannot get key by id");
        let label_colour = Color::Dark(BaseColor::Blue);
        let mut output = StyledString::new();
        output.append_plain(key.arn_string());
        output.append_plain("\n\n");
        output.append_styled("Key ID:      ", label_colour);
        output.append_plain(format!("{}", key.key_id()));
        output.append_plain("\n");
        output.append_styled("Region:      ", label_colour);
        output.append_plain(key.region());
        output.append_plain("\n");
        output.append_styled("Account ID:  ", label_colour);
        output.append_plain(key.account_id());
        output.append_plain("\n");
        output.append_styled("Created:     ", label_colour);
        output.append_plain(format!("{}", key.created()));
        output.append_plain("\n");
        output.append_styled("Kind:        ", label_colour);
        output.append_plain(format!("{}", key.kind()));
        output.append_plain("\n");
        output.append_styled("State:       ", label_colour);
        output.append_plain(format!("{}", key.state()));
        output.append_plain("\n");
        output.append_styled("Description: ", label_colour);
        let mut description = key.description();
        if description.is_empty() {
            description = "[None]";
        }
        output.append_plain(description);
        output.append_plain("\n");
        let aliases: Vec<String> = self.key_store.authorised_aliases(&BrowserAuthorisation)
            .filter(|&(_, k)| k.key_id() == key_id)
            .map(|(alias_arn, _)| AliasArn::parse(alias_arn, true).expect("invalid alias exists").name().to_owned())
            .collect();
        if !aliases.is_empty() {
            output.append_styled("Aliases:", label_colour);
            for alias in aliases.iter() {
                output.append_plain("\n    ");
                output.append_plain(alias.as_str())
            }
            output.append_plain("\n");
        }
        let tags = key.tags();
        if !tags.is_empty() {
            output.append_styled("Tags:", label_colour);
            for tag in tags.iter() {
                output.append_plain(format!("\n    {}: {}", tag.key(), tag.value()))
            }
            output.append_plain("\n");
        }
        text_view.set_content(output);
    }

    fn delete_key(&mut self, key_id: &Uuid) {
        self.key_store.remove_key(key_id)
            .expect("cannot delete key");
    }
}

struct BrowserAuthorisation;

impl Authorisation for BrowserAuthorisation {
    fn region(&self) -> &str {
        unreachable!()
    }

    fn account_id(&self) -> &str {
        unreachable!()
    }

    fn authorise_body(&self, _body: &str) -> Result<(), AuthorisationError> {
        Ok(())
    }

    fn authorises_access(&self, _key: &Key, access: Access) -> Result<(), AuthorisationError> {
        if access == Access::Default {
            Ok(())
        } else {
            Err(AuthorisationError::Unauthorised)
        }
    }
}
