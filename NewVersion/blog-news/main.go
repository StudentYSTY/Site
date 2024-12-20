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
	ID        int
	Username  string
	Password  string
	IsBlocked bool
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
	r.HandleFunc("/edit-news/{id}", editNewsHandler).Methods("GET", "POST")
	r.HandleFunc("/delete-news/{id}", deleteNewsHandler).Methods("POST")
	r.HandleFunc("/logout", logoutHandler).Methods("GET")
	r.HandleFunc("/admin", adminHandler).Methods("GET")
	r.HandleFunc("/admin/delete-user/{id}", deleteUserHandler).Methods("POST")
	r.HandleFunc("/admin/block-user/{id}", blockUserHandler).Methods("POST")
	r.HandleFunc("/admin/unblock-user/{id}", unblockUserHandler).Methods("POST")

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
		err := db.QueryRow("SELECT id, username, password, is_blocked FROM users WHERE username = $1",
			username).Scan(&user.ID, &user.Username, &user.Password, &user.IsBlocked)

		if err == nil {
			if user.IsBlocked {
				http.Error(w, "Ваш аккаунт заблокирован", http.StatusForbidden)
				return
			}
			if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) == nil {
				session, _ := store.Get(r, "session-name")
				session.Values["authenticated"] = true
				session.Values["username"] = username
				session.Save(r, w)
				http.Redirect(w, r, "/", http.StatusSeeOther)
				return
			}
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

func editNewsHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	log.Println("Editing news with ID:", id)

	if r.Method == "POST" {
		title := r.FormValue("title")
		content := r.FormValue("content")

		_, err := db.Exec("UPDATE news SET title = $1, content = $2 WHERE id = $3", title, content, id)
		if err != nil {
			http.Error(w, "Ошибка при редактировании новости", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	var news News
	err := db.QueryRow("SELECT id, title, content FROM news WHERE id = $1", id).Scan(&news.ID, &news.Title, &news.Content)
	if err != nil {
		http.Error(w, "Новость не найдена", http.StatusNotFound)
		return
	}

	data := struct {
		News            News
		IsAuthenticated bool
	}{
		News:            news,
		IsAuthenticated: isAuthenticated(r),
	}

	log.Println("Передача данных в шаблон:", data)

	err = templates.ExecuteTemplate(w, "edit_news.html", data)
	if err != nil {
		log.Println("Ошибка при отображении шаблона:", err)
		http.Error(w, "Ошибка при отображении шаблона", http.StatusInternalServerError)
		return
	}
}

func deleteNewsHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	_, err := db.Exec("DELETE FROM news WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Ошибка при удалении новости", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	if !isAuthenticated(r) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	rows, err := db.Query("SELECT id, username, is_blocked FROM users")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		err := rows.Scan(&user.ID, &user.Username, &user.IsBlocked)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	templates.ExecuteTemplate(w, "admin.html", struct{ Users []User }{Users: users})
}

func deleteUserHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	_, err := db.Exec("DELETE FROM users WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Ошибка при удалении пользователя", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func blockUserHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	_, err := db.Exec("UPDATE users SET is_blocked = TRUE WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Ошибка при блокировке пользователя", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func unblockUserHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	_, err := db.Exec("UPDATE users SET is_blocked = FALSE WHERE id = $1", id)
	if err != nil {
		http.Error(w, "Ошибка при разблокировке пользователя", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}
