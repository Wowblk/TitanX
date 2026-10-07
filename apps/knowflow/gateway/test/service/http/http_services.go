package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
)

func startUserService(wg *sync.WaitGroup) {
	defer wg.Done()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"service": "user", "path": "%s", "port": "8381"}`, r.URL.Path)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received health check for user service")
		fmt.Fprintf(w, `{"health":"ok"}`)
	})
	server := &http.Server{Addr: ":8381", Handler: mux}
	fmt.Println("User Service running on :8381")
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("User Service failed:", err)
	}
}

func startUserService2(wg *sync.WaitGroup) {
	defer wg.Done()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"service": "user", "path": "%s", "port": "8383"}`, r.URL.Path)
	})
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received health check for user service")
		fmt.Fprintf(w, `{"health":"ok"}`)
	})
	server := &http.Server{Addr: ":8383", Handler: mux}
	fmt.Println("User Service 2 running on :8383")
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("User Service 2 failed:", err)
	}
}

func startOrderService(wg *sync.WaitGroup) {
	defer wg.Done()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"service": "order", "path": "%s", "port": "8382"}`, r.URL.Path)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Received health check for order service")
		fmt.Fprintf(w, `{"health":"ok"}`)
	})
	server := &http.Server{Addr: ":8382", Handler: mux}
	fmt.Println("Order Service running on :8382")
	if err := server.ListenAndServe(); err != nil {
		fmt.Println("Order Service failed:", err)
	}
}

func main() {
	var wg sync.WaitGroup
	wg.Add(3)

	go startUserService(&wg)
	go startUserService2(&wg)
	go startOrderService(&wg)

	wg.Wait()
}
