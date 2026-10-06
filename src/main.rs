use argospass::{Entry, Vault};

fn main() {
    let mut vault = Vault::new();
    vault.add(Entry::new(
        "Gmail",
        "moi@gmail.com",
        "test-1",
        "https://gmail.com",
    ));
    vault.add(Entry::new(
        "GitHub",
        "aymeric",
        "test-2",
        "https://gmail.com",
    ));

    println!("Entrées :");
    for entry in vault.list() {
        println!("- {} ({})", entry.title, entry.username);
    }

    match vault.get("GitHub") {
        Some(entry) => println!("Mot de passe GitHub : {}", entry.password),
        None => println!("Entrée introuvable"),
    }

    vault.remove("Gmail");
    println!("{} entrée(s) restante(s)", vault.list().len());
}
