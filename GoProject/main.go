package main

import (
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"html/template"
	"net/http"
)

type User struct {
	Name     string
	Email    string
	Login    string
	Password int
}

func (u *User) getAllInfo() string {
	return fmt.Sprintf("Hello Dear: %s.", u.Name)
}

func (u *User) setNewName(newName string) {
	u.Name = newName
}

func home_page(w http.ResponseWriter, r *http.Request) {
	goblin := User{"Ilya", "Gob@mala.ru", "GoblinUser", 1313}
	//goblin.setNewName("T2X2T")
	//fmt.Fprintf(w, goblin.getAllInfo())
	tmpl, _ := template.ParseFiles("HTML/home_page.html")
	tmpl.Execute(w, goblin)
}

func contacts_page(w http.ResponseWriter, r *http.Request) {
	fmt.Print("Contacts: ")
}

func Autorization_page(w http.ResponseWriter, r *http.Request) {

}

func handleRequest() {
	http.HandleFunc("/", home_page)
	http.HandleFunc("/contacts/", contacts_page)
	http.HandleFunc("/Autorization/", Autorization_page)
	http.ListenAndServe(":8080", nil)
}
func main() {
	//goblin := User{email: "Gob@mala.ru", Login: "GoblinUser", Password: 1313}

	db, err := sql.Open("mysql", "root:root@tcp(127.0.0.1:8889)/goland")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	fmt.Println("Connected to database ")

	handleRequest()
}
