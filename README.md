# pwdhash-webextension

Welcome to PwdHash webextension for firefox

## description

Automatically generates per-site passwords if you prefix your password with @@ or press F2 beforehand.
Prevents JavaScript from reading your password as it is typed.
The same password will be generated at each subdomain: a.example.com matches b.example.com, a.example.co.uk
matches b.example.co.uk, but a.co.uk and b.co.uk are different.

Hashed passwords can also be generated at https://www.pwdhash.com/

## roadmap

* add option to highlight password field
* add PBKDF2-SHA512 as alternative to MD5
* add user salt option


Go Check It Out
