#![deny(unused_must_use)]

#[macro_use]
extern crate log;

use std::cell::RefCell;
use std::rc::Rc;

use base64::encode as b64encode;
use chrono::{DateTime, Utc};
use cursive::Cursive;
use cursive::event::Key as KeyEvent;
use cursive::theme::{Palette, BaseColor, Color, Theme};
use cursive::traits::*;
use cursive::utils::markup::StyledString;
use cursive::view::SizeConstraint;
use cursive::views::{BoxView, Dialog, DummyView, LinearLayout, PaddedView, Panel, ScrollView, SelectView, TextView};

use rusty_kms::key_store::{Arn, KeyStore};

fn main() {
    env_logger::from_env(env_logger::Env::default().default_filter_or("browser=info")).init();

    let app = clap::App::new("Rusty KMS store browser").version(env!("CARGO_PKG_VERSION"))
        .arg(clap::Arg::with_name("data_path").long("data")
            .help("Key store directory")
            .required(true)
            .takes_value(true))
        .arg(clap::Arg::with_name("show_key_material").long("show-key-material")
            .help("Show secret key material in browser"));
    let args = app.get_matches();

    let show_key_material = args.is_present("show_key_material");
    if show_key_material {
        warn!("Key material will be revealed");
    }

    let key_store = KeyStore::new(args.value_of("data_path"));
    let key_store_details = KeyStoreDetails { show_key_material, key_store };
    show_browser(key_store_details);
}

fn show_browser(key_store_details: KeyStoreDetails) {
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

    let key_store_details = Rc::new(RefCell::new(key_store_details));

    let key_store_details_clone = Rc::clone(&key_store_details);
    let delete_lock = Rc::new(RefCell::new(false));
    siv.add_global_callback(KeyEvent::Backspace, move |s: &mut Cursive| {
        if *delete_lock.borrow() {
            return;
        }
        if let Some(arn) = s.find_id::<SelectView>("list")
            .map(|view| view.selection())
            .unwrap_or(None) {
            if arn.is_empty() {
                return;
            }
            *delete_lock.borrow_mut() = true;
            let delete_lock1 = Rc::clone(&delete_lock);
            let delete_lock2 = Rc::clone(&delete_lock);
            let key_store_details = Rc::clone(&key_store_details_clone);
            let prompt = Dialog::text("Do you want to delete this key?")
                .button("Cancel", move |s: &mut Cursive| {
                    s.pop_layer();
                    *delete_lock1.borrow_mut() = false;
                })
                .button("Delete", move |s: &mut Cursive| {
                    let mut key_store_details = key_store_details.borrow_mut();
                    key_store_details.delete_key(&arn);
                    s.call_on_id("list", |list_view: &mut SelectView| {
                        list_view.clear();
                        refresh_list(list_view, key_store_details.key_list());
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
    let mut list_view = SelectView::new();
    refresh_list(&mut list_view, key_store_details.borrow().key_list());
    list_view.set_on_submit(move |s, arn: &str| {
        if arn.is_empty() {
            return;
        }
        s.call_on_id("detail", |text_view: &mut TextView| {
            key_store_details.borrow().display_details(text_view, arn);
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

fn refresh_list(list_view: &mut SelectView, key_list: Vec<(String, String)>) {
    list_view.add_all(key_list);
    if list_view.is_empty() {
        list_view.add_item("(None)", String::default());
    }
    // TODO: need to trigger layout?
}

struct KeyStoreDetails {
    show_key_material: bool,
    key_store: KeyStore,
}

impl KeyStoreDetails {
    fn key_list(&self) -> Vec<(String, String)> {
        let mut key_list: Vec<(&DateTime<Utc>, &str, &str)> = self.key_store.key_iter()
            .map(|key| (key.created(), key.key_id(), key.arn().arn_str()))
            .collect();
        key_list.sort_by_key(|&(created, _, _)| created);
        key_list.iter()
            .map(|&(_, key_id, arn)| (key_id.to_owned(), arn.to_owned()))
            .rev()
            .collect()
    }

    fn display_details(&self, text_view: &mut TextView, arn: &str) {
        let key = &self.key_store[arn];
        let label_colour = Color::Dark(BaseColor::Blue);
        let mut output = StyledString::new();
        output.append_plain(key.arn().arn_str());
        output.append_plain("\n\n");
        output.append_styled("Key ID:      ", label_colour);
        output.append_plain(key.key_id());
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
        let aliases = self.key_store.aliases_for(key.arn().arn_str());
        if !aliases.is_empty() {
            output.append_styled("Aliases:", label_colour);
            for item in aliases {
                output.append_plain("\n    ");
                output.append_plain(item.as_str())
            }
            output.append_plain("\n");
        }
        let tags = key.tags();
        if !tags.is_empty() {
            output.append_styled("Tags:", label_colour);
            for item in tags.iter().map(|(key, value)| format!("\n    {}: {}", key, value)) {
                output.append_plain(item.as_str())
            }
            output.append_plain("\n");
        }
        if self.show_key_material && key.has_key_material() {
            output.append_styled("\n\nKey material:", label_colour);
            for item in key.key_material().iter().map(b64encode) {
                output.append_plain("\n    ");
                output.append_plain(item.as_str())
            }
        }
        text_view.set_content(output);
    }

    fn delete_key(&mut self, arn: &str) {
        self.key_store.delete_key(arn);
    }
}
