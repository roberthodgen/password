# password
> A Golang password hashing, salting, and matching library.

```bash
$ go get -u github.com/roberthodgen/password
```

This is an opinionated library for password hashing and matching. It simply concatenates a plain text password with a salt then hashes it! Also provides random salt generation. Reasonable defaults are made but overrideable.


## Matching Usage

**The simplest usage is:**

```go
checker := password.NewChecker(storedHash, storedSalt)
if err := checker.Check(plainTextPasswordAttempt); err != nil {
	// An error occurred and the password may not have matched the hash and salt...
	return err
}
```

`err` may be non-`nil` if:
1. Couldn't match the `plainTextPasswordAttempt` to the `storedHash` and `storedSalt`.
2. Or the `storedSalt` couldn't be converted from hex to `[]byte` via `hex.DecodeString`.


**Catching just incorrect passwords:**

`ErrIncorrect` is available for you error checking pleasure...

```go
checker := password.NewChecker(storedHash, storedSalt)
if err := checker.Check(plainTextPasswordAttempt); err == password.ErrIncorrect {
	// The password did not match!
} else if err != nil {
	// Another error prevented the attempting password check, likely `storedSalt` isn't hex-encoded
}
// If you're here everything's fine and `plainTextPasswordAttempt` matched!
```


# Generating

Generating password hashes and salts is easy:

```go
pass := password.New()
if err := pass.Generate(plainTextPasswordToHash); err != nil {
	// Oops! Something went wrong (likely couldn't read from random)
}
someUserHash := pass.Hash // the plain text + salt hash
someUserSalt := pass.Salt // the randomly generated salt
```


# More

There's more! Like the Hash struct below. This exposes the ability to change the hash algorithm used (default is `crypto/sha256`) as well as new salt generation length (in bytes).

```go
type Hash struct {
	SaltLength int // number of random bytes to read in Hash.Generate
	HashFn     hash.Hash // the hash function to be used
	Hash       string // the supplied or computed hash of (plain text bytes + salt bytes)
	Salt       string // the supplied or generated random salt
}
```

Assumptions are made that you will check the plain text passwords for complexity requirements. No complexity checks are made in this library.

Because a single Hash shares the HashFn: Hash is not safe to share between threads!

Enjoy :)
