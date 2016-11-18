package devportal

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"strings"

	"github.com/boltdb/bolt"
)

var bucketNames = []string{
	"accounts",
	"plugins",
	"index:emailsToAccounts",
	"notifications",
}

func openDB(file string) (*bolt.DB, error) {
	db, err := bolt.Open(file, 0600, nil)
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, bucket := range bucketNames {
			_, err := tx.CreateBucketIfNotExists([]byte(bucket))
			if err != nil {
				return fmt.Errorf("create bucket %s: %v", bucket, err)
			}
		}
		return nil
	})
	return db, err
}

func loadAccount(acctID string) (AccountInfo, error) {
	var acc AccountInfo
	err := loadFromDB(&acc, "accounts", acctID)
	if err != nil {
		return acc, err
	}
	if acc.ID != acctID {
		return acc, fmt.Errorf("no account with ID '%s'", acctID)
	}
	return acc, nil
}

func saveAccount(acc AccountInfo) error {
	err := saveToDB("accounts", acc.ID, acc)
	if err != nil {
		return err
	}
	emailKey := strings.ToLower(acc.Email) // email is not case-sensitive
	return saveToDBRaw("index:emailsToAccounts", []byte(emailKey), []byte(acc.ID))
}

func saveToDB(bucket, key string, val interface{}) error {
	enc, err := gobEncode(val)
	if err != nil {
		return fmt.Errorf("error encoding for database: %v", err)
	}
	return saveToDBRaw(bucket, []byte(key), enc)
}

func saveToDBRaw(bucket string, key, val []byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		return b.Put(key, val)
	})
}

func loadFromDB(into interface{}, bucket, key string) error {
	return db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		v := b.Get([]byte(key))
		if v != nil {
			return gobDecode(v, into)
		}
		return nil
	})
}

func isUnique(bucket, key string) bool {
	var unique bool
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		unique = b.Get([]byte(key)) == nil
		return nil
	})
	return unique
}

func gobEncode(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(value)
	return buf.Bytes(), err
}

func gobDecode(buf []byte, into interface{}) error {
	dec := gob.NewDecoder(bytes.NewReader(buf))
	return dec.Decode(into)
}
