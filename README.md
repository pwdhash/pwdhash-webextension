# pwdhash-webextension

PwdHash webextension for firefox

## Description

Automatically generates per-site passwords if you prefix your password with @@ or press F2 beforehand.
Prevents JavaScript from reading your password as it is typed.
The same password will be generated at each subdomain: a.example.com matches b.example.com, a.example.co.uk
matches b.example.co.uk, but a.co.uk and b.co.uk are different.

Hashed passwords can also be generated at https://www.pwdhash.com/

## Roadmap

* Add option to highlight password field
* Add PBKDF2-SHA512 as alternative to MD5
* Add user salt option
