package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "modernc.org/sqlite"
)

func queryDB() {
	db, err := sql.Open("sqlite", "C:/Users/BrianSuin/AppData/Roaming/VeriHash/proof_of_work.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	var payloadStr string
	err = db.QueryRow("SELECT full_vc_json FROM session_credentials WHERE vc_id = \"urn:uuid:ebf8b7cf109dcc0ef112361d2dbe8cc412355548d58d43ebb6e949efb37380be\"").Scan(&payloadStr)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(payloadStr)
}
