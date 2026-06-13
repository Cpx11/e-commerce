# e-commerce
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Allow read/write based on admin status
    function isAdmin() {
      return request.auth != null && 
        exists(/databases/$(database)/documents/users/$(request.auth.uid)) &&
        get(/databases/$(database)/documents/users/$(request.auth.uid)).data.role == 'admin';
    }
    
    // Users collection - only the user themselves or admin
    match /users/{userId} {
      allow read: if request.auth != null && (request.auth.uid == userId || isAdmin());
      allow write: if request.auth != null && request.auth.uid == userId;
    }
    
    // Categories - public read, admin write
    match /categories/{document} {
      allow read: if true;
      allow write: if isAdmin();
      allow list, get: if true;
    }
    
    // Products - public read, admin write
    match /products/{document} {
      allow read: if true;
      allow write: if isAdmin();
      allow list, get: if true;
    }
    
    // Orders - admin only
    match /orders/{document} {
      allow read, write: if isAdmin();
      allow list, get: if isAdmin();
    }
    
    // Settings - admin only
    match /settings/{document} {
      allow read, write: if isAdmin();
      allow list, get: if isAdmin();
    }
    
    // Notifications - admin only for reads, users for their own
    match /notifications/{document} {
      allow read: if isAdmin();
      allow write: if isAdmin();
    }
    
    // Customers - admin only
    match /customers/{document} {
      allow read, write: if isAdmin();
      allow list, get: if isAdmin();
    }
    
    // PromoCodes - admin only
    match /promoCodes/{document} {
      allow read, write: if isAdmin();
      allow list, get: if isAdmin();
    }
  }
}