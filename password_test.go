package password

import (
	"testing"
	"crypto/sha256"
	"reflect"
)

func TestNew(t *testing.T) {
	h := New()

	if h.Salt != "" {
		t.Error("Salt should be empty.")
	}

	if h.Hash != "" {
		t.Error("Hash should be empty.")
	}

	sha256HashFn := sha256.New()
	if reflect.TypeOf(h.HashFn) != reflect.TypeOf(sha256HashFn) {
		t.Error("expected to be a sha256 digest")
	}

	if h.SaltLength != DefaultSaltLength {
		t.Error("expected SaltLength to be DefaultSaltLength")
	}
}

func TestNewPasswordChecker(t *testing.T) {
	myHash := "0f3520c0e4de843a14c441cde417fbbab2e336d9502a998374c7e907020e2e47"
	mySalt := "890c5970bb07262e"
	h := NewChecker(myHash, mySalt)

	if h.Salt != mySalt {
		t.Error("Salt should be preset.")
	}

	if h.Hash != myHash {
		t.Error("Hash should be preset.")
	}

	sha256HashFn := sha256.New()
	if reflect.TypeOf(h.HashFn) != reflect.TypeOf(sha256HashFn) {
		t.Error("expected to be a sha256 digest")
	}

	if h.SaltLength != DefaultSaltLength {
		t.Error("expected SaltLength to be DefaultSaltLength")
	}
}

func TestHash_Check(t *testing.T) {
	myHash := "0f3520c0e4de843a14c441cde417fbbab2e336d9502a998374c7e907020e2e47"
	mySalt := "890c5970bb07262e"
	checker := NewChecker(myHash, mySalt)

	if err := checker.Check("test"); err != nil {
		t.Errorf("should have matched password, instead got: %v", err)
	}

	if err := checker.Check("totallywrongpassword"); err != ErrIncorrect {
		t.Errorf("expected ErrIncorrect (incorrect password), instead got: %v", err)
	}
}

func TestHash_Generate(t *testing.T) {
	h := New()
	if err := h.Generate("N01C@nGue$$MySup3rS3cr3tP4$$w0rd!"); err != nil {
		t.Errorf("should have generated, inead got: %v", err)
	}

	t.Logf("Generated Salt: %s", h.Salt)
	t.Logf("Generated Hash: %s", h.Hash)

	// Should be able to turn around and test immediately
	if err := h.Check("N01C@nGue$$MySup3rS3cr3tP4$$w0rd!"); err != nil {
		t.Errorf("should have matched password, instead got: %v", err)
	}

	if err := h.Check("wrong"); err != ErrIncorrect {
		t.Errorf("expected ErrIncorrect (incorrect password), instead got: %v", err)
	}
}
