package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"math"
	"os"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	at "github.com/positiveblue/adaptive-table"
	murmur3 "github.com/spaolacci/murmur3"
)

type Signature struct {
	name            string
	seed            uint64
	totalElements   int
	cardinality     int
	fingerprintSize int
	fingerprint     []uint64
}

func (s *Signature) Save(db *sql.DB) {
	sqlAddSignature := `
	INSERT OR REPLACE INTO Signatures(
		Name,
		Seed,
		TotalElements,
		Cardinality,
		FingerprintSize
	) values(?, ?, ?, ?, ?)
	`

	signatureStmt, err := db.Prepare(sqlAddSignature)
	if err != nil {
		panic(err)
	}
	defer signatureStmt.Close()

	_, err = signatureStmt.Exec(s.name, s.seed, s.totalElements, s.cardinality, s.fingerprintSize)
	if err != nil {
		panic(err)
	}

	sqlAddFingerprintValue := `
	INSERT OR REPLACE INTO FingerpintValues(
		Name,
		Value
	) values(?, ?)
	`
	fingerprintValueStmt, err := db.Prepare(sqlAddFingerprintValue)
	if err != nil {
		panic(err)
	}
	defer signatureStmt.Close()
	for _, value := range s.fingerprint {
		_, err = fingerprintValueStmt.Exec(s.name, value)
		if err != nil {
			panic(err)
		}
	}
}

func (s *Signature) Load(name string, db *sql.DB) {
	sqlSelectFileName := fmt.Sprintf(`
	SELECT Name, Seed, TotalElements, Cardinality, FingerprintSize
	FROM Signatures
	WHERE Name="%v"
	`, name)

	rows, err := db.Query(sqlSelectFileName)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	if !rows.Next() {
		fmt.Printf("%s has not been added to the database yet/n", name)
		return
	}

	rows.Scan(&s.name, &s.seed, &s.totalElements, &s.cardinality, &s.fingerprintSize)
}

func (s *Signature) LoadFingerprint(db *sql.DB) {
	sqlSelectFileName := fmt.Sprintf(`
	SELECT Value
	FROM FingerpintValues
	WHERE Name="%v"
	`, s.name)

	rows, err := db.Query(sqlSelectFileName)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var hash uint64
	var fingerpint []uint64
	counter := 0
	for rows.Next() {
		counter++
		rows.Scan(&hash)
		fingerpint = append(fingerpint, hash)
	}
	s.fingerprint = fingerpint
	fmt.Printf("Counter =========  %v/n", counter)
}

// Calculate cardinality
func EstimateCardinality(table at.AdaptiveTable, initialSize int) int {
	if table.Size() < initialSize {
		return table.Size()
	}

	meanDistance := table.Max() / uint64(table.Size())
	return int(math.MaxUint64 / meanDistance)
}

// DB
func InitDB(filepath string) *sql.DB {
	db, err := sql.Open("sqlite3", filepath)
	if err != nil {
		panic(err)
	}
	if db == nil {
		panic("db nil")
	}
	return db
}

func createTable(db *sql.DB, sql_code string) {
	_, err := db.Exec(sql_code)
	if err != nil {
		fmt.Printf("%v", err)
		panic(err)
	}
}

func CreateDBTables(db *sql.DB) {
	// create tables if not exists
	tables := []string{
		// Signatures table
		`
		CREATE TABLE IF NOT EXISTS Signatures(
			Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			Name TEXT,
			Seed INTEGER,
			TotalElements ITEGER,
			Cardinality INTEGER,
			FingerprintSize INTEGER
		);
		`,
		// Signature Values
		`
		CREATE TABLE IF NOT EXISTS FingerpintValues(
			Id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
			Name TEXT,
			Value INTEGER
		);
		`,
	}

	for _, sql_code := range tables {
		createTable(db, sql_code)
	}
}

func ListFileNames(db *sql.DB) {
	sql_readall := `
	SELECT Name
	FROM Signatures;
	`

	rows, err := db.Query(sql_readall)
	if err != nil {
		panic(err)
	}
	defer rows.Close()

	var name string
	for rows.Next() {
		rows.Scan(&name)
		fmt.Printf("%v n", name)
	}
}

func SearchFileName(name string, fingerprint bool, db *sql.DB) {
	var s Signature
	s.Load(name, db)

	fmt.Printf("Name: %v\n", s.name)
	fmt.Printf("Seed: %v\n", s.seed)
	fmt.Printf("Elements: %v\n", s.totalElements)
	fmt.Printf("Cardinality: %v\n", s.cardinality)
	fmt.Printf("Fingerprint size: %v\n", s.fingerprintSize)

	if fingerprint {
		s.LoadFingerprint(db)
		fmt.Printf("Fingerprint: \n")

		for i, value := range s.fingerprint {
			fmt.Println(i, value)
		}
	}
}

// IO
func getScanner(fileName string) *bufio.Scanner {
	if fileName != "" {
		f, err := os.Open(fileName)
		if err != nil {
			panic(err)
		}
		return bufio.NewScanner(f)
	} else {
		panic("No arguments")
	}
}

func main() {
	sizePtr := flag.Int("size", 64, "Initial size for the adaptive-table")
	seedPtr := flag.Uint64("seed", 42, "Seed used by Murmurhash")
	dbPathPtr := flag.String("dbpath", "signatures.db", "Database file path")
	printFingerprintPtr := flag.Bool("fingerprint", false, "True if you want to print the fingerprint")

	flag.Parse()

	dbpath := *dbPathPtr
	size := *sizePtr
	seed := uint32(*seedPtr)
	printFingerpint := *printFingerprintPtr

	// Init db
	db := InitDB(dbpath)
	defer db.Close()
	CreateDBTables(db)

	// Generate signature for each one of the files
	for _, arg := range flag.Args() {
		scanner := getScanner(arg)
		counter := 0
		table := at.NewAdaptiveTableComplete(size, math.MaxInt64, size)

		for scanner.Scan() {
			for _, word := range strings.Fields(scanner.Text()) {
				counter++
				hash := murmur3.Sum64WithSeed([]byte(word), seed)
				table.Insert(hash)
			}
		}

		if err := scanner.Err(); err != nil {
			panic(err)
		}

		cardinality := EstimateCardinality(table, size)
		fingerprintSize := table.Size()
		var fingerprint []uint64
		for i := 0; i < fingerprintSize; i++ {
			fingerprint = append(fingerprint, table.Pop())
		}

		signature := Signature{
			name:            arg,
			seed:            *seedPtr,
			totalElements:   counter,
			cardinality:     cardinality,
			fingerprintSize: fingerprintSize,
			fingerprint:     fingerprint,
		}

		signature.Save(db)
	}

	//ListFileNames(db)
	SearchFileName(flag.Args()[0], printFingerpint, db)
}
