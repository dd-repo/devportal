package devportal

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"math/rand"
	"os"
	"strings"

	"github.com/boltdb/bolt"
)

// The list of bucket names to require in the database.
var bucketNames = []string{
	"accounts",
	"caddyReleases",
	"cachedBuilds",
	"index:emailsToAccounts",
	"index:namesToPlugins",
	"notifications",
	"plugins",
	//"pluginsCachedBuilds",
}

// openDB opens the database at file and returns it,
// ready to use.
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

// loadAccount loads the account given by acctID from the DB.
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

// saveAccount saves acc to the DB.
func saveAccount(acc AccountInfo) error {
	err := saveToDB("accounts", acc.ID, acc)
	if err != nil {
		return err
	}
	emailKey := strings.ToLower(acc.Email) // email is not case-sensitive
	return saveToDBRaw("index:emailsToAccounts", []byte(emailKey), []byte(acc.ID))
}

// saveCachedBuild saves cb to the database.
// If the cache is full, it deletes a random
// cached build.
func saveCachedBuild(cb CachedBuild) error {
	err := cachedBuildsMaintenance()
	if err != nil {
		return err
	}
	return saveToDB("cachedBuilds", cb.CacheKey, cb)
}

// cachedBuildsMaintenance deletes 'random' cached builds.
// It chooses a random key to delete, then deletes it and
// as many subsequent keys as needed to get the number of
// cached builds within the maximum.
func cachedBuildsMaintenance() error {
	var shortStraws []CachedBuild

	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("cachedBuilds"))
		numCachedBuilds := b.Stats().KeyN
		excessBuilds := numCachedBuilds - MaxCachedBuilds
		if excessBuilds > 0 {
			randomIndex := rand.Intn(numCachedBuilds - excessBuilds + 1)
			c := b.Cursor()
			i := 0
			for k, v := c.First(); k != nil; k, v = c.Next() {
				if i >= randomIndex {
					var shortStraw CachedBuild
					err := gobDecode(v, &shortStraw)
					if err != nil {
						return err
					}
					shortStraws = append(shortStraws, shortStraw)
					if len(shortStraws) >= excessBuilds {
						break
					}
				}
				i++
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	for _, shortStraw := range shortStraws {
		err := deleteCachedBuild(shortStraw)
		if err != nil {
			return err
		}
	}
	return nil
}

// deleteCachedBuild deletes cb from disk and the database.
func deleteCachedBuild(cb CachedBuild) error {
	return db.Update(func(tx *bolt.Tx) error {
		err := os.RemoveAll(cb.Dir)
		if err != nil {
			return err
		}
		b := tx.Bucket([]byte("cachedBuilds"))
		return b.Delete([]byte(cb.CacheKey))
	})
}

// saveCaddyRelease saves this Caddy release rel to the DB.
func saveCaddyRelease(rel CaddyRelease) error {
	tsKey := rel.Timestamp.Format(tsKeyFormat) // key order is important
	return saveToDB("caddyReleases", tsKey, rel)
}

// savePluginRelease saves rel for the plugin with pluginID.
func savePluginRelease(pluginID string, rel PluginRelease) error {
	pl, err := loadPlugin(pluginID)
	if err != nil {
		return err
	}
	pl.Releases = append(pl.Releases, rel)
	return savePlugin(pl)
}

// loadLatestCaddyRelease loads the latest Caddy release from the DB.
// If there is no release, an error is returned.
func loadLatestCaddyRelease() (CaddyRelease, error) {
	var rel CaddyRelease
	err := db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte("caddyReleases"))
		key, _ := bucket.Cursor().Last()
		return loadFromBucket(&rel, bucket, key)
	})
	if rel.Version == "" || rel.Timestamp.IsZero() {
		return rel, fmt.Errorf("no caddy releases")
	}
	return rel, err
}

// savePlugin saves pl into the database.
func savePlugin(pl Plugin) error {
	err := saveToDB("plugins", pl.ID, pl)
	if err != nil {
		return err
	}
	return saveToDBRaw("index:namesToPlugins", []byte(pl.Name), []byte(pl.ID))
}

// loadAllPlugins loads all the plugins from the database,
// optionally filtered by ownerID (account ID).
func loadAllPlugins(ownerID string) ([]Plugin, error) {
	var plugins []Plugin
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("plugins"))
		return b.ForEach(func(k, v []byte) error {
			var pl Plugin
			err := gobDecode(v, &pl)
			if err != nil {
				return err
			}
			if ownerID == "" || pl.OwnerAccountID == ownerID {
				plugins = append(plugins, pl)
			}
			return nil
		})
	})
	return plugins, err
}

// loadPlugin loads the plugin by pluginID.
func loadPlugin(pluginID string) (Plugin, error) {
	var pl Plugin
	err := loadFromDB(&pl, "plugins", pluginID)
	if err != nil {
		return pl, err
	}
	if pl.ID != pluginID {
		return pl, fmt.Errorf("no plugin with ID '%s'", pluginID)
	}
	return pl, nil
}

// loadCachedBuild loads the build cached by cacheKey.
// The second return value will be true if a match was found.
func loadCachedBuild(cacheKey string) (CachedBuild, bool, error) {
	var cb CachedBuild
	err := loadFromDB(&cb, "cachedBuilds", cacheKey)
	if err != nil {
		return cb, false, err
	}
	return cb, cb.CacheKey == cacheKey, nil
}

// evictBuildsFromCache will delete builds from the cache so as
// to avoid serving stale content. For example, if a plugin is
// deployed at a branch, the branch name may not change even
// though its ref does; thus, the cache key will be the same
// even though content is different.
//
// If you specify a plugin ID and version, all cache entries
// configured with that plugin at that version will be evicted.
// If a Caddy version is specified, all cache entries configured
// with that version of Caddy will be evicted. Only evict for
// either a plugin or Caddy, not both (it is an error).
func evictBuildsFromCache(pluginID, pluginVersion, caddyVersion string) error {
	if (pluginID == "" && pluginVersion != "") || (pluginID != "" && pluginVersion == "") {
		return fmt.Errorf("to evict by plugin, must have plugin ID and version")
	}
	if pluginID != "" && caddyVersion != "" {
		return fmt.Errorf("cannot evict cache based on both plugin and Caddy versions")
	}
	var cachedBuildsToDelete []CachedBuild
	err := db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket([]byte("cachedBuilds")).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var cb CachedBuild
			err := gobDecode(v, &cb)
			if err != nil {
				return err
			}
			if caddyVersion != "" && cb.Config.CaddyVersion == caddyVersion {
				// evict based on Caddy version
				cachedBuildsToDelete = append(cachedBuildsToDelete, cb)
				continue
			}
			for _, plugin := range cb.Config.Plugins {
				if plugin.ID == pluginID && plugin.Version == pluginVersion {
					// evict based on plugin version
					cachedBuildsToDelete = append(cachedBuildsToDelete, cb)
					break
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte("cachedBuilds"))
		for _, cb := range cachedBuildsToDelete {
			err := os.RemoveAll(cb.Dir)
			if err != nil {
				return err
			}
			err = b.Delete([]byte(cb.CacheKey))
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// loadPluginByName loads the plugin by pluginName.
func loadPluginByName(pluginName string) (Plugin, error) {
	var pl Plugin
	pluginID, err := loadFromDBRaw("index:namesToPlugins", pluginName)
	if err != nil {
		return pl, err
	}
	if len(pluginID) == 0 {
		return pl, fmt.Errorf("no plugin named '%s'", pluginName)
	}
	return loadPlugin(string(pluginID))
}

// saveToDB saves val by key into bucket by gob-encoding it.
func saveToDB(bucket, key string, val interface{}) error {
	enc, err := gobEncode(val)
	if err != nil {
		return fmt.Errorf("error encoding for database: %v", err)
	}
	return saveToDBRaw(bucket, []byte(key), enc)
}

// saveToDBRaw saves the value with key in bucket.
func saveToDBRaw(bucket string, key, val []byte) error {
	return db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		return b.Put(key, val)
	})
}

// loadFromBucket loads key from bucket into into, decoded.
func loadFromBucket(into interface{}, bucket *bolt.Bucket, key []byte) error {
	v := bucket.Get([]byte(key))
	if v != nil {
		return gobDecode(v, into)
	}
	return nil
}

// loadFromDB loads key from bucket into into, decoded.
func loadFromDB(into interface{}, bucket, key string) error {
	return db.View(func(tx *bolt.Tx) error {
		return loadFromBucket(into, tx.Bucket([]byte(bucket)), []byte(key))
	})
}

// loadFromDBRaw loads the value from bucket at key, no decoding.
func loadFromDBRaw(bucket, key string) ([]byte, error) {
	var v []byte
	return v, db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		v = b.Get([]byte(key))
		return nil
	})
}

// uniqueID generates a random string that is not yet
// used as a key in the given bucket.
func uniqueID(bucket string) (string, error) {
	const idLen = 10
	id := randString(idLen)
	for i, maxTries := 0, 50; !isUnique(bucket, id) && i < maxTries; i++ {
		if i == maxTries-1 {
			return "", fmt.Errorf("no unique IDs available as key for bucket '%s'", bucket)
		}
		id = randString(idLen)
	}
	return id, nil
}

// isUnique returns true if key is not found in bucket.
func isUnique(bucket, key string) bool {
	var unique bool
	db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucket))
		unique = b.Get([]byte(key)) == nil
		return nil
	})
	return unique
}

// gobEncode gob encodes value.
func gobEncode(value interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(value)
	return buf.Bytes(), err
}

// gobDecode gob decodes buf into into.
func gobDecode(buf []byte, into interface{}) error {
	dec := gob.NewDecoder(bytes.NewReader(buf))
	return dec.Decode(into)
}

const tsKeyFormat = "2006-01-02 15:04:05.000" // for where chronological key order is important
