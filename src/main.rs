use argospass::Entry;

fn main() {
    let entry = Entry::new(
        "Gmail",
        "moi@gmail.com",
        "mot-de-passe-de-test",
        "https://gmail.com",
    );
    println!("{} : {}", entry.title, entry.username);
}
