use minidom::Element;

const NS: &str = "ns";
const TITLE: &str = "Title";
const PASSWORD: &str = "Password";
const USERNAME: &str = "UserName";
const URL: &str = "URL";
const UUID: &str = "UUID";
const NAME: &str = "Name";

#[derive(Debug)]
pub struct Content {
    root_group: Group,
}

#[derive(Debug)]
pub struct ContentEntry {
    uuid: String,
    title: String,
    password: String,
    username: String,
    url: String,
}

#[derive(Debug)]
pub struct Group {
    uuid: String,
    name: String,
    entries: Vec<ContentEntry>,
}

impl Content {
    pub fn new(doc: Element) -> Self {
        let mut root_group = Group {
            entries: vec![],
            name: "".into(),
            uuid: "".into(),
        };

        let root = doc.get_child("Root", NS).unwrap();

        root.children().for_each(|group| {
            if group.name() == "Group" {
                root_group.name = group.get_child(NAME, NS).unwrap().text();
                root_group.uuid = group.get_child(UUID, NS).unwrap().text();

                group.children().for_each(|entry| {
                    if entry.name() == "Entry" {
                        root_group.entries.push(ContentEntry::new(entry));
                    }
                })
            }
        });

        Content { root_group }
    }
}

impl ContentEntry {
    pub fn new(entry: &Element) -> Self {
        let mut content = ContentEntry {
            title: "".into(),
            password: "".into(),
            username: "".into(),
            url: "".into(),
            uuid: "".into(),
        };

        entry.children().for_each(|kv| {
            if kv.name() == "String" {
                let key = kv.get_child("Key", NS).unwrap().text();
                let value = kv.get_child("Value", NS).unwrap().text();

                match key.as_str() {
                    TITLE => content.title = value,
                    PASSWORD => content.password = value,
                    USERNAME => content.username = value,
                    URL => content.url = value,
                    UUID => content.uuid = value,
                    _ => {}
                }
            }
        });
        content
    }
}
