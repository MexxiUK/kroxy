package store

import (
	"os"
	"testing"
)

func TestStore_CRUD(t *testing.T) {
	tmp, err := os.CreateTemp("", "kroxy-test-*.db")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmp.Name())
	tmp.Close()

	s, err := New(tmp.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Test Create
	route := &Route{
		Domain:     "example.com",
		Backend:    "http://localhost:3000",
		Enabled:    true,
		WAFEnabled: true,
	}
	if err := s.CreateRoute(route); err != nil {
		t.Fatalf("CreateRoute failed: %v", err)
	}
	if route.ID == 0 {
		t.Fatal("Expected route ID to be set")
	}

	// Test Read
	routes, err := s.GetRoutes()
	if err != nil {
		t.Fatalf("GetRoutes failed: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("Expected 1 route, got %d", len(routes))
	}
	if routes[0].Domain != "example.com" {
		t.Fatalf("Expected domain example.com, got %s", routes[0].Domain)
	}

	// Test Update
	route.Backend = "http://localhost:4000"
	if err := s.UpdateRoute(route); err != nil {
		t.Fatalf("UpdateRoute failed: %v", err)
	}

	// Test Delete
	if err := s.DeleteRoute(route.ID); err != nil {
		t.Fatalf("DeleteRoute failed: %v", err)
	}

	routes, err = s.GetRoutes()
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 0 {
		t.Fatalf("Expected 0 routes after delete, got %d", len(routes))
	}
}