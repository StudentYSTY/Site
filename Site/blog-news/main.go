package main

import (
	"database/sql"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"html/template"
	"log"
	"net/http"
	"time"
)

type User struct {
	ID       int
	Username string
	Password string
}

type News struct {
	ID        int
	Title     string
	Content   string
	CreatedAt time.Time
}

var (
	db        *sql.DB
	templates *template.Template
	store     = sessions.NewCookieStore([]byte("secret-key-123"))
)

func init() {
	connStr := "postgres://postgres:1121@localhost/webapp?sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	templates = template.Must(template.ParseGlob("templates/*.html"))
}

func isAuthenticated(r *http.Request) bool {
	session, _ := store.Get(r, "session-name")
	auth, ok := session.Values["authenticated"].(bool)
	return ok && auth
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/", homeHandler).Methods("GET")
	r.HandleFunc("/register", registerHandler).Methods("GET", "POST")
	r.HandleFunc("/login", loginHandler).Methods("GET", "POST")
	r.HandleFunc("/add-news", addNewsHandler).Methods("GET", "POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")

	r.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	log.Fatal(http.ListenAndServe(":8080", r))
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, title, content, created_at FROM news ORDER BY created_at DESC")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var news []News
	for rows.Next() {
		var n News
		err := rows.Scan(&n.ID, &n.Title, &n.Content, &n.CreatedAt)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		news = append(news, n)
	}

	data := struct {
		News            []News
		IsAuthenticated bool
	}{
		News:            news,
		IsAuthenticated: isAuthenticated(r),
	}

	templates.ExecuteTemplate(w, "index.html", data)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Ошибка при регистрации", http.StatusInternalServerError)
			return
		}

		_, err = db.Exec("INSERT INTO users (username, password) VALUES ($1, $2)",
			username, string(hashedPassword))
		if err != nil {
			http.Error(w, "Пользователь уже существует", http.StatusBadRequest)
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "register.html", struct{ IsAuthenticated bool }{IsAuthenticated: isAuthenticated(r)})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var user User
		err := db.QueryRow("SELECT id, username, password FROM users WHERE username = $1",
			username).Scan(&user.ID, &user.Username, &user.Password)

		if err == nil && bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil {
			session, _ := store.Get(r, "session-name")
			session.Values["authenticated"] = true
			session.Values["username"] = username
			session.Save(r, w)
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		http.Error(w, "Неверные учетные данные", http.StatusUnauthorized)
		return
	}

	templates.ExecuteTemplate(w, "login.html", struct{ IsAuthenticated bool }{IsAuthenticated: isAuthenticated(r)})
}

func addNewsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		title := r.FormValue("title")
		content := r.FormValue("content")

		_, err := db.Exec("INSERT INTO news (title, content, created_at) VALUES ($1, $2, $3)",
			title, content, time.Now())
		if err != nil {
			http.Error(w, "Ошибка при добавлении новости", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "add_news.html", struct{ IsAuthenticated bool }{IsAuthenticated: isAuthenticated(r)})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := store.Get(r, "session-name")
	session.Values["authenticated"] = false
	session.Values["username"] = ""
	session.Save(r, w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
