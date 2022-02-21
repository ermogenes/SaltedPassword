# SaltedPassword
A simple utility to create and test salted-hash password with PBKDF2/SHA256

## Usage
Add the package to your project:
```
dotnet add package Ermogenes.SaltedPassword --version 1.0.1
```

```cs
using Ermogenes.SaltedPassword;
```

Getting a key from a clear password:
```cs
string keyToStore = SaltedPassword.GetPersistentKey(clearPassword);
```

The value of `keyToStore` is a salted-hash from the `clearPassword`, and may be stored.

The format: 
```
base64-salt|number-of-iterations|base64-hash
```

Testing a password for equality:
```cs
bool passwordMatch = SaltedPassword.Match(clearPasswordToMatch, storedKey);
```

## Test
```
git clone https://github.com/ermogenes/SaltedPassword
cd SaltedPassword
dotnet test
```

## Reference
[OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

## License
[MIT License](LICENSE)
